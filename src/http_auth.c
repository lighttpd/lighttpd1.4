#include "first.h"

#include "server.h"
#include "log.h"
#include "http_auth.h"
#include "stream.h"
#include "base64.h"

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#elif defined(__linux__)
/* linux needs _XOPEN_SOURCE */
# define _XOPEN_SOURCE
#endif

#if defined(HAVE_LIBCRYPT) && !defined(HAVE_CRYPT)
/* always assume crypt() is present if we have -lcrypt */
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

#include "md5.h"

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#endif

#include "safe_memclear.h"


/**
 * the $apr1$ handling is taken from apache 1.3.x
 */

/*
 * The apr_md5_encode() routine uses much code obtained from the FreeBSD 3.0
 * MD5 crypt() function, which is licenced as follows:
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

static int http_auth_get_password(server *srv, mod_auth_plugin_data *p, const buffer *username, const buffer *realm, buffer *password) {
	if (buffer_is_empty(username) || buffer_is_empty(realm)) return -1;

	if (p->conf.auth_backend == AUTH_BACKEND_HTDIGEST) {
		FILE *fp;
		char f_user[1024];

		if (buffer_string_is_empty(p->conf.auth_htdigest_userfile)) return -1;

		fp = fopen(p->conf.auth_htdigest_userfile->ptr, "r");
		if (NULL == fp) {
			log_error_write(srv, __FILE__, __LINE__, "sbss", "opening digest-userfile", p->conf.auth_htdigest_userfile, "failed:", strerror(errno));

			return -1;
		}

		while (NULL != fgets(f_user, sizeof(f_user), fp)) {
			char *f_pwd, *f_realm;
			size_t u_len, r_len;

			/* skip blank lines and comment lines (beginning '#') */
			if (f_user[0] == '#' || f_user[0] == '\n' || f_user[0] == '\0') continue;

			/*
			 * htdigest format
			 *
			 * user:realm:md5(user:realm:password)
			 */

			if (NULL == (f_realm = strchr(f_user, ':'))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"parsed error in", p->conf.auth_htdigest_userfile,
						"expected 'username:realm:hashed password'");

				continue; /* skip bad lines */
			}

			if (NULL == (f_pwd = strchr(f_realm + 1, ':'))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"parsed error in", p->conf.auth_plain_userfile,
						"expected 'username:realm:hashed password'");

				continue; /* skip bad lines */
			}

			/* get pointers to the fields */
			u_len = f_realm - f_user;
			f_realm++;
			r_len = f_pwd - f_realm;
			f_pwd++;

			if (buffer_string_length(username) == u_len &&
			    (buffer_string_length(realm) == r_len) &&
			    (0 == strncmp(username->ptr, f_user, u_len)) &&
			    (0 == strncmp(realm->ptr, f_realm, r_len))) {
				/* found */

				size_t pwd_len = strlen(f_pwd);
				if (f_pwd[pwd_len-1] == '\n') --pwd_len;

				buffer_copy_string_len(password, f_pwd, pwd_len);

				fclose(fp);
				return 0;
			}
		}

		fclose(fp);
	} else if (p->conf.auth_backend == AUTH_BACKEND_HTPASSWD ||
		   p->conf.auth_backend == AUTH_BACKEND_PLAIN) {
		FILE *fp;
		char f_user[1024];
		buffer *auth_fn;

		auth_fn = (p->conf.auth_backend == AUTH_BACKEND_HTPASSWD) ? p->conf.auth_htpasswd_userfile : p->conf.auth_plain_userfile;

		if (buffer_string_is_empty(auth_fn)) return -1;

		fp = fopen(auth_fn->ptr, "r");
		if (NULL == fp) {
			log_error_write(srv, __FILE__, __LINE__, "sbss",
					"opening plain-userfile", auth_fn, "failed:", strerror(errno));

			return -1;
		}

		while (NULL != fgets(f_user, sizeof(f_user), fp)) {
			char *f_pwd;
			size_t u_len;

			/* skip blank lines and comment lines (beginning '#') */
			if (f_user[0] == '#' || f_user[0] == '\n' || f_user[0] == '\0') continue;

			/*
			 * htpasswd format
			 *
			 * user:crypted passwd
			 */

			if (NULL == (f_pwd = strchr(f_user, ':'))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"parsed error in", auth_fn,
						"expected 'username:hashed password'");

				continue; /* skip bad lines */
			}

			/* get pointers to the fields */
			u_len = f_pwd - f_user;
			f_pwd++;

			if (buffer_string_length(username) == u_len &&
			    (0 == strncmp(username->ptr, f_user, u_len))) {
				/* found */

				size_t pwd_len = strlen(f_pwd);
				if (f_pwd[pwd_len-1] == '\n') --pwd_len;

				buffer_copy_string_len(password, f_pwd, pwd_len);

				fclose(fp);
				return 0;
			}
		}

		fclose(fp);
	} else if (p->conf.auth_backend == AUTH_BACKEND_LDAP) {
		return -1; /* should not happen */
	} else if (p->conf.auth_backend == AUTH_BACKEND_UNSET) {
		log_error_write(srv, __FILE__, __LINE__, "s", "auth.backend is not set");
	}

	return -1;
}

int http_auth_get_password_digest(server *srv, mod_auth_plugin_data *p, const char *username, const char *realm, unsigned char HA1[16]) {
	buffer *username_buf = buffer_init_string(username);
	buffer *realm_buf = buffer_init_string(realm);
	buffer *password = buffer_init();
	int rc = 1;

	if (http_auth_get_password(srv, p, username_buf, realm_buf, password)) {
		rc = 0;
	} else if (p->conf.auth_backend == AUTH_BACKEND_PLAIN) {
		/* generate password from plain-text */
		li_MD5_CTX Md5Ctx;
		li_MD5_Init(&Md5Ctx);
		li_MD5_Update(&Md5Ctx, (unsigned char *)username_buf->ptr, buffer_string_length(username_buf));
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, (unsigned char *)realm_buf->ptr, buffer_string_length(realm_buf));
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, CONST_BUF_LEN(password));
		li_MD5_Final(HA1, &Md5Ctx);
	} else if (p->conf.auth_backend == AUTH_BACKEND_HTDIGEST) {
		/* HA1 */
		/* transform the 32-byte-hex-md5 to a 16-byte-md5 */
		int i;
		for (i = 0; i < 16; i++) {
			HA1[i] = hex2int(password->ptr[i*2]) << 4;
			HA1[i] |= hex2int(password->ptr[i*2+1]);
		}
	} else {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"digest: unsupported backend (only htdigest or plain)");
		rc = -1;
	}

	buffer_free(username_buf);
	buffer_free(realm_buf);
	buffer_free(password);
	return rc;
}

#define APR_MD5_DIGESTSIZE 16
#define APR1_ID "$apr1$"

/*
 * The following MD5 password encryption code was largely borrowed from
 * the FreeBSD 3.0 /usr/src/lib/libcrypt/crypt.c file, which is
 * licenced as stated at the top of this file.
 */

static void to64(char *s, unsigned long v, int n)
{
	static const unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	while (--n >= 0) {
		*s++ = itoa64[v&0x3f];
		v >>= 6;
	}
}

static void apr_md5_encode(const char *pw, const char *salt, char *result, size_t nbytes) {
	/*
	 * Minimum size is 8 bytes for salt, plus 1 for the trailing NUL,
	 * plus 4 for the '$' separators, plus the password hash itself.
	 * Let's leave a goodly amount of leeway.
	 */

	char passwd[120], *p;
	const char *sp, *ep;
	unsigned char final[APR_MD5_DIGESTSIZE];
	ssize_t sl, pl, i;
	li_MD5_CTX ctx, ctx1;
	unsigned long l;

	/*
	 * Refine the salt first.  It's possible we were given an already-hashed
	 * string as the salt argument, so extract the actual salt value from it
	 * if so.  Otherwise just use the string up to the first '$' as the salt.
	 */
	sp = salt;

	/*
	 * If it starts with the magic string, then skip that.
	 */
	if (!strncmp(sp, APR1_ID, strlen(APR1_ID))) {
		sp += strlen(APR1_ID);
	}

	/*
	 * It stops at the first '$' or 8 chars, whichever comes first
	 */
	for (ep = sp; (*ep != '\0') && (*ep != '$') && (ep < (sp + 8)); ep++) {
		continue;
	}

	/*
	 * Get the length of the true salt
	 */
	sl = ep - sp;

	/*
	 * 'Time to make the doughnuts..'
	 */
	li_MD5_Init(&ctx);

	/*
	 * The password first, since that is what is most unknown
	 */
	li_MD5_Update(&ctx, pw, strlen(pw));

	/*
	 * Then our magic string
	 */
	li_MD5_Update(&ctx, APR1_ID, strlen(APR1_ID));

	/*
	 * Then the raw salt
	 */
	li_MD5_Update(&ctx, sp, sl);

	/*
	 * Then just as many characters of the MD5(pw, salt, pw)
	 */
	li_MD5_Init(&ctx1);
	li_MD5_Update(&ctx1, pw, strlen(pw));
	li_MD5_Update(&ctx1, sp, sl);
	li_MD5_Update(&ctx1, pw, strlen(pw));
	li_MD5_Final(final, &ctx1);
	for (pl = strlen(pw); pl > 0; pl -= APR_MD5_DIGESTSIZE) {
		li_MD5_Update(
			&ctx, final,
			(pl > APR_MD5_DIGESTSIZE) ? APR_MD5_DIGESTSIZE : pl);
	}

	/*
	 * Don't leave anything around in vm they could use.
	 */
	memset(final, 0, sizeof(final));

	/*
	 * Then something really weird...
	 */
	for (i = strlen(pw); i != 0; i >>= 1) {
		if (i & 1) {
			li_MD5_Update(&ctx, final, 1);
		}
		else {
			li_MD5_Update(&ctx, pw, 1);
		}
	}

	/*
	 * Now make the output string.  We know our limitations, so we
	 * can use the string routines without bounds checking.
	 */
	strcpy(passwd, APR1_ID);
	strncat(passwd, sp, sl);
	strcat(passwd, "$");

	li_MD5_Final(final, &ctx);

	/*
	 * And now, just to make sure things don't run too fast..
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for (i = 0; i < 1000; i++) {
		li_MD5_Init(&ctx1);
		if (i & 1) {
			li_MD5_Update(&ctx1, pw, strlen(pw));
		}
		else {
			li_MD5_Update(&ctx1, final, APR_MD5_DIGESTSIZE);
		}
		if (i % 3) {
			li_MD5_Update(&ctx1, sp, sl);
		}

		if (i % 7) {
			li_MD5_Update(&ctx1, pw, strlen(pw));
		}

		if (i & 1) {
			li_MD5_Update(&ctx1, final, APR_MD5_DIGESTSIZE);
		}
		else {
			li_MD5_Update(&ctx1, pw, strlen(pw));
		}
		li_MD5_Final(final,&ctx1);
	}

	p = passwd + strlen(passwd);

	l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(p, l, 4); p += 4;
	l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(p, l, 4); p += 4;
	l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(p, l, 4); p += 4;
	l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(p, l, 4); p += 4;
	l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(p, l, 4); p += 4;
	l =                    final[11]                ; to64(p, l, 2); p += 2;
	*p = '\0';

	/*
	 * Don't leave anything around in vm they could use.
	 */
	safe_memclear(final, sizeof(final));

	/* FIXME
	 */
#define apr_cpystrn strncpy
	apr_cpystrn(result, passwd, nbytes - 1);
}

#ifdef USE_OPENSSL
static void apr_sha_encode(const char *pw, char *result, size_t nbytes) {
	unsigned char digest[20];
	size_t base64_written;

	SHA1((const unsigned char*) pw, strlen(pw), digest);

	memset(result, 0, nbytes);

	/* need 5 bytes for "{SHA}", 28 for base64 (3 bytes -> 4 bytes) of SHA1 (20 bytes), 1 terminating */
	if (nbytes < 5 + 28 + 1) return;

	memcpy(result, "{SHA}", 5);
	base64_written = li_to_base64(result + 5, nbytes - 5, digest, 20, BASE64_STANDARD);
	force_assert(base64_written == 28);
	result[5 + base64_written] = '\0'; /* terminate string */
}
#endif

/**
 *
 *
 * @param password password-string from the auth-backend
 * @param pw       password-string from the client
 */

#ifdef USE_LDAP
static int http_auth_basic_password_compare_ldap(server *srv, mod_auth_plugin_data *p, buffer *username, const char *pw);
#endif

int http_auth_basic_password_compare(server *srv, mod_auth_plugin_data *p, buffer *username, buffer *realm, const char *pw) {
	int rc = -1;
	buffer *password;

#ifdef USE_LDAP
	if (p->conf.auth_backend == AUTH_BACKEND_LDAP) {
		return http_auth_basic_password_compare_ldap(srv, p, username, pw);
	}
#endif

	password = buffer_init();
	if (http_auth_get_password(srv, p, username, realm, password)) {
		rc = -1;
	}
	else if (p->conf.auth_backend == AUTH_BACKEND_HTDIGEST) {
		/*
		 * htdigest format
		 *
		 * user:realm:md5(user:realm:password)
		 */

		li_MD5_CTX Md5Ctx;
		unsigned char HA1[16];
		char a1[33];

		li_MD5_Init(&Md5Ctx);
		li_MD5_Update(&Md5Ctx, CONST_BUF_LEN(username));
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, CONST_BUF_LEN(realm));
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, (unsigned char *)pw, strlen(pw));
		li_MD5_Final(HA1, &Md5Ctx);

		li_tohex(a1, sizeof(a1), (const char *)HA1, sizeof(HA1));

		rc = strcmp(password->ptr, a1);
	} else if (p->conf.auth_backend == AUTH_BACKEND_HTPASSWD) {
		char sample[120];
		if (!strncmp(password->ptr, APR1_ID, strlen(APR1_ID))) {
			/*
			 * The hash was created using $apr1$ custom algorithm.
			 */
			apr_md5_encode(pw, password->ptr, sample, sizeof(sample));
			rc = strcmp(sample, password->ptr);
#ifdef USE_OPENSSL
		} else if (0 == strncmp(password->ptr, "{SHA}", 5)) {
			apr_sha_encode(pw, sample, sizeof(sample));
			rc = strcmp(sample, password->ptr);
#endif
		} else if (buffer_string_length(password) < 13) {
			/* a simple DES password is 2 + 11 characters. everything else should be longer. */
			rc = -1;
		} else {
#if defined(HAVE_CRYPT_R) || defined(HAVE_CRYPT)
			char *crypted;
#if defined(HAVE_CRYPT_R)
			struct crypt_data crypt_tmp_data;
			crypt_tmp_data.initialized = 0;
			crypted = crypt_r(pw, password->ptr, &crypt_tmp_data);
#else
			crypted = crypt(pw, password->ptr);
#endif
			if (NULL != crypted) {
				rc = strcmp(password->ptr, crypted);
			}
#endif
		}
	} else if (p->conf.auth_backend == AUTH_BACKEND_PLAIN) {
		rc = strcmp(password->ptr, pw);
	}

	buffer_free(password);

	return rc;
}

#ifdef USE_LDAP

handler_t auth_ldap_init(server *srv, mod_auth_plugin_config *s);

static int http_auth_basic_password_compare_ldap(server *srv, mod_auth_plugin_data *p, buffer *username, const char *pw) {
		LDAP *ldap;
		LDAPMessage *lm, *first;
		char *dn;
		int ret;
		char *attrs[] = { LDAP_NO_ATTRS, NULL };
		size_t i, len;

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

		len = buffer_string_length(username);
		for (i = 0; i < len; i++) {
			char c = username->ptr[i];

			if (!isalpha(c) &&
			    !isdigit(c) &&
			    (c != ' ') &&
			    (c != '@') &&
			    (c != '-') &&
			    (c != '_') &&
			    (c != '.') ) {

				log_error_write(srv, __FILE__, __LINE__, "sbd",
					"ldap: invalid character (- _.@a-zA-Z0-9 allowed) in username:", username, i);

				return -1;
			}
		}

		if (p->conf.auth_ldap_allow_empty_pw != 1 && pw[0] == '\0')
			return -1;

		/* build filter */
		buffer_copy_buffer(p->ldap_filter, p->conf.ldap_filter_pre);
		buffer_append_string_buffer(p->ldap_filter, username);
		buffer_append_string_buffer(p->ldap_filter, p->conf.ldap_filter_post);


		/* 2. */
		if (p->anon_conf->ldap == NULL ||
		    LDAP_SUCCESS != (ret = ldap_search_s(p->anon_conf->ldap, p->conf.auth_ldap_basedn->ptr, LDAP_SCOPE_SUBTREE, p->ldap_filter->ptr, attrs, 0, &lm))) {

			/* try again; the ldap library sometimes fails for the first call but reconnects */
			if (p->anon_conf->ldap == NULL || ret != LDAP_SERVER_DOWN ||
			    LDAP_SUCCESS != (ret = ldap_search_s(p->anon_conf->ldap, p->conf.auth_ldap_basedn->ptr, LDAP_SCOPE_SUBTREE, p->ldap_filter->ptr, attrs, 0, &lm))) {

				if (auth_ldap_init(srv, p->anon_conf) != HANDLER_GO_ON)
					return -1;

				if (NULL == p->anon_conf->ldap) return -1;

				if (LDAP_SUCCESS != (ret = ldap_search_s(p->anon_conf->ldap, p->conf.auth_ldap_basedn->ptr, LDAP_SCOPE_SUBTREE, p->ldap_filter->ptr, attrs, 0, &lm))) {
					log_error_write(srv, __FILE__, __LINE__, "sssb",
							"ldap:", ldap_err2string(ret), "filter:", p->ldap_filter);
					return -1;
				}
			}
		}

		if (NULL == (first = ldap_first_entry(p->anon_conf->ldap, lm))) {
			log_error_write(srv, __FILE__, __LINE__, "s", "ldap ...");

			ldap_msgfree(lm);

			return -1;
		}

		if (NULL == (dn = ldap_get_dn(p->anon_conf->ldap, first))) {
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
}
#endif
