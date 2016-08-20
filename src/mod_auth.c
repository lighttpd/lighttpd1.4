#include "first.h"

#include "plugin.h"
#include "http_auth.h"
#include "log.h"
#include "response.h"

#include "inet_ntop_cache.h"
#include "base64.h"
#include "md5.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * the basic and digest auth framework
 */

typedef struct {
	/* auth */
	array  *auth_require;

	buffer *auth_plain_groupfile;
	buffer *auth_plain_userfile;

	buffer *auth_htdigest_userfile;
	buffer *auth_htpasswd_userfile;

	buffer *auth_backend_conf;

	unsigned short auth_debug;

	/* generated */
	const http_auth_backend_t *auth_backend;
} mod_auth_plugin_config;

typedef struct {
	PLUGIN_DATA;
	buffer *tmp_buf;

	mod_auth_plugin_config **config_storage;

	mod_auth_plugin_config conf;
} mod_auth_plugin_data;

INIT_FUNC(mod_auth_init) {
	mod_auth_plugin_data *p;

	p = calloc(1, sizeof(*p));

	p->tmp_buf = buffer_init();

	return p;
}

FREE_FUNC(mod_auth_free) {
	mod_auth_plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	buffer_free(p->tmp_buf);

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			mod_auth_plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			array_free(s->auth_require);
			buffer_free(s->auth_backend_conf);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_auth_patch_connection(server *srv, connection *con, mod_auth_plugin_data *p) {
	size_t i, j;
	mod_auth_plugin_config *s = p->config_storage[0];

	PATCH(auth_backend);
	PATCH(auth_require);
	PATCH(auth_debug);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend"))) {
				PATCH(auth_backend);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.require"))) {
				PATCH(auth_require);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.debug"))) {
				PATCH(auth_debug);
			}
		}
	}

	return 0;
}
#undef PATCH

static int mod_auth_match_rules(server *srv, array *req, const char *username, const char *group, const char *host) {
	const char *r = NULL, *rules = NULL;
	int username_len;
	data_string *require;

	UNUSED(group);
	UNUSED(host);

	require = (data_string *)array_get_element(req, "require");
	if (!require) return -1; /*(should not happen; config is validated at startup)*/

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
			log_error_write(srv, __FILE__, __LINE__, "sb",
					"parsing the 'require' section in 'auth.require' failed: valid-user cannot be combined with other require rules",
					require->value);
			return -1;
		}

		/* search for = in the rules */
		if (NULL == (eq = strchr(r, '='))) {
			log_error_write(srv, __FILE__, __LINE__, "sb",
					"parsing the 'require' section in 'auth.require' failed: a = is missing",
					require->value);
			return -1;
		}

		/* = out of range */
		if (eq > r + r_len) {
			log_error_write(srv, __FILE__, __LINE__, "sb",
					"parsing the 'require' section in 'auth.require' failed: = out of range",
					require->value);

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

static handler_t mod_auth_send_400_bad_request(server *srv, connection *con) {
	UNUSED(srv);

	/* a field was missing or invalid */
	con->http_status = 400; /* Bad Request */
	con->mode = DIRECT;

	return HANDLER_FINISHED;
}

static int mod_auth_digest_generate_nonce(server *srv, mod_auth_plugin_data *p, buffer *fn, char (*out)[33]);

static handler_t mod_auth_send_401_unauthorized_basic(server *srv, connection *con, mod_auth_plugin_data *p, array *req) {
	data_string *realm = (data_string *)array_get_element(req, "realm");

	con->http_status = 401;
	con->mode = DIRECT;

	if (!realm) return HANDLER_FINISHED; /*(should not happen; config is validated at startup)*/

	buffer_copy_string_len(p->tmp_buf, CONST_STR_LEN("Basic realm=\""));
	buffer_append_string_buffer(p->tmp_buf, realm->value);
	buffer_append_string_len(p->tmp_buf, CONST_STR_LEN("\", charset=\"UTF-8\""));

	response_header_insert(srv, con, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(p->tmp_buf));

	return HANDLER_FINISHED;
}

static handler_t mod_auth_send_401_unauthorized_digest(server *srv, connection *con, mod_auth_plugin_data *p, array *req, int nonce_stale) {
	data_string *realm = (data_string *)array_get_element(req, "realm");
	char hh[33];

	con->http_status = 401;
	con->mode = DIRECT;

	if (!realm) return HANDLER_FINISHED; /*(should not happen; config is validated at startup)*/

	/* using unknown contents of srv->tmp_buf (modified elsewhere)
	 * adds dubious amount of randomness.  Remove use of srv->tmp_buf? */
	mod_auth_digest_generate_nonce(srv, p, srv->tmp_buf, &hh);

	buffer_copy_string_len(p->tmp_buf, CONST_STR_LEN("Digest realm=\""));
	buffer_append_string_buffer(p->tmp_buf, realm->value);
	buffer_append_string_len(p->tmp_buf, CONST_STR_LEN("\", charset=\"UTF-8\", nonce=\""));
	buffer_append_uint_hex(p->tmp_buf, (uintmax_t)srv->cur_ts);
	buffer_append_string_len(p->tmp_buf, CONST_STR_LEN(":"));
	buffer_append_string(p->tmp_buf, hh);
	buffer_append_string_len(p->tmp_buf, CONST_STR_LEN("\", qop=\"auth\""));
	if (nonce_stale) {
		buffer_append_string_len(p->tmp_buf, CONST_STR_LEN(", stale=true"));
	}

	response_header_insert(srv, con, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(p->tmp_buf));

	return HANDLER_FINISHED;
}

static void mod_auth_setenv(server *srv, connection *con, const char *username, size_t ulen, const char *auth_type, size_t alen) {
	data_string *ds;
	UNUSED(srv);

	/* the REMOTE_USER header */

	if (NULL == (ds = (data_string *)array_get_element(con->environment, "REMOTE_USER"))) {
		if (NULL == (ds = (data_string *)array_get_unused_element(con->environment, TYPE_STRING))) {
			ds = data_string_init();
		}
		buffer_copy_string_len(ds->key, CONST_STR_LEN("REMOTE_USER"));
		array_insert_unique(con->environment, (data_unset *)ds);
	}
	buffer_copy_string_len(ds->value, username, ulen);

	/* AUTH_TYPE environment */

	if (NULL == (ds = (data_string *)array_get_element(con->environment, "AUTH_TYPE"))) {
		if (NULL == (ds = (data_string *)array_get_unused_element(con->environment, TYPE_STRING))) {
			ds = data_string_init();
		}
		buffer_copy_string_len(ds->key, CONST_STR_LEN("AUTH_TYPE"));
		array_insert_unique(con->environment, (data_unset *)ds);
	}
	buffer_copy_string_len(ds->value, auth_type, alen);
}

static handler_t mod_auth_basic_check(server *srv, connection *con, mod_auth_plugin_data *p, array *req, const char *realm_str) {
	buffer *username;
	char *pw;

	data_string *realm;

	realm = (data_string *)array_get_element(req, "realm");
	if (!realm) { /*(should not happen; config is validated at startup)*/
		return mod_auth_send_400_bad_request(srv, con);
	}

	username = buffer_init();

	if (!buffer_append_base64_decode(username, realm_str, strlen(realm_str), BASE64_STANDARD)) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "decodeing base64-string failed", username);

		buffer_free(username);
		return mod_auth_send_400_bad_request(srv, con);
	}

	/* r2 == user:password */
	if (NULL == (pw = strchr(username->ptr, ':'))) {
		log_error_write(srv, __FILE__, __LINE__, "sb", ": is missing in", username);

		buffer_free(username);
		return mod_auth_send_400_bad_request(srv, con);
	}

	buffer_string_set_length(username, pw - username->ptr);
	pw++;

	switch (p->conf.auth_backend->basic(srv, con, p->conf.auth_backend->p_d, username, realm->value, pw)) {
	case HANDLER_GO_ON:
		break;
	case HANDLER_WAIT_FOR_EVENT:
		buffer_free(username);
		return HANDLER_WAIT_FOR_EVENT;
	case HANDLER_FINISHED:
		buffer_free(username);
		return HANDLER_FINISHED;
	case HANDLER_ERROR:
	default:
		log_error_write(srv, __FILE__, __LINE__, "sbsBss", "password doesn't match for", con->uri.path, "username:", username, ", IP:", inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
		buffer_free(username);
		return mod_auth_send_401_unauthorized_basic(srv, con, p, req);
	}

	/* value is our allow-rules */
	if (mod_auth_match_rules(srv, req, username->ptr, NULL, NULL)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "rules didn't match");

		buffer_free(username);
		return mod_auth_send_401_unauthorized_basic(srv, con, p, req);
	}

	mod_auth_setenv(srv, con, CONST_BUF_LEN(username), CONST_STR_LEN("Basic"));

	buffer_free(username);

	return HANDLER_GO_ON;
}

#define HASHLEN 16
#define HASHHEXLEN 32
typedef unsigned char HASH[HASHLEN];
typedef char HASHHEX[HASHHEXLEN+1];

static void CvtHex(const HASH Bin, char (*Hex)[33]) {
	li_tohex(*Hex, sizeof(*Hex), (const char*) Bin, 16);
}

typedef struct {
	const char *key;
	int key_len;
	char **ptr;
} digest_kv;

static handler_t mod_auth_digest_check(server *srv, connection *con, mod_auth_plugin_data *p, array *req, const char *realm_str) {
	char a1[33];
	char a2[33];

	char *username = NULL;
	char *realm = NULL;
	char *nonce = NULL;
	char *uri = NULL;
	char *algorithm = NULL;
	char *qop = NULL;
	char *cnonce = NULL;
	char *nc = NULL;
	char *respons = NULL;

	char *e, *c;
	const char *m = NULL;
	int i;
	buffer *b;

	li_MD5_CTX Md5Ctx;
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

	b = buffer_init_string(realm_str);

	/* parse credentials from client */
	for (c = b->ptr; *c; c++) {
		/* skip whitespaces */
		while (*c == ' ' || *c == '\t') c++;
		if (!*c) break;

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
				break;
			}
		}
	}

	if (p->conf.auth_debug > 1) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "username", username);
		log_error_write(srv, __FILE__, __LINE__, "ss", "realm", realm);
		log_error_write(srv, __FILE__, __LINE__, "ss", "nonce", nonce);
		log_error_write(srv, __FILE__, __LINE__, "ss", "uri", uri);
		log_error_write(srv, __FILE__, __LINE__, "ss", "algorithm", algorithm);
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
	    (qop && (!nc || !cnonce)) ||
	    !respons ) {
		/* missing field */

		log_error_write(srv, __FILE__, __LINE__, "s",
				"digest: missing field");

		buffer_free(b);
		return mod_auth_send_400_bad_request(srv, con);
	}

	/**
	 * protect the md5-sess against missing cnonce and nonce
	 */
	if (algorithm &&
	    0 == strcasecmp(algorithm, "md5-sess") &&
	    (!nonce || !cnonce)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"digest: (md5-sess: missing field");

		buffer_free(b);
		return mod_auth_send_400_bad_request(srv, con);
	}

	if (qop && strcasecmp(qop, "auth-int") == 0) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"digest: qop=auth-int not supported");

		buffer_free(b);
		return mod_auth_send_400_bad_request(srv, con);
	}

	m = get_http_method_name(con->request.http_method);
	force_assert(m);

	/* detect if attacker is attempting to reuse valid digest for one uri
	 * on a different request uri.  Might also happen if intermediate proxy
	 * altered client request line.  (Altered request would not result in
	 * the same digest as that calculated by the client.)
	 * Internal redirects such as with mod_rewrite will modify request uri.
	 * Reauthentication is done to detect crossing auth realms, but this
	 * uri validation step is bypassed.  con->request.orig_uri is original
	 * uri sent in client request. */
	{
		const size_t ulen = strlen(uri);
		const size_t rlen = buffer_string_length(con->request.orig_uri);
		if (!buffer_is_equal_string(con->request.orig_uri, uri, ulen)
		    && !(rlen < ulen && 0 == memcmp(con->request.orig_uri->ptr, uri, rlen) && uri[rlen] == '?')) {
			log_error_write(srv, __FILE__, __LINE__, "sbssss",
					"digest: auth failed: uri mismatch (", con->request.orig_uri, "!=", uri, "), IP:", inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
			buffer_free(b);
			return mod_auth_send_400_bad_request(srv, con);
		}
	}

	/* password-string == HA1 */
	switch (p->conf.auth_backend->digest(srv, con, p->conf.auth_backend->p_d, username, realm, HA1)) {
	case HANDLER_GO_ON:
		break;
	case HANDLER_WAIT_FOR_EVENT:
		buffer_free(b);
		return HANDLER_WAIT_FOR_EVENT;
	case HANDLER_FINISHED:
		buffer_free(b);
		return HANDLER_FINISHED;
	case HANDLER_ERROR:
	default:
		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(srv, con, p, req, 0);
	}

	if (algorithm &&
	    strcasecmp(algorithm, "md5-sess") == 0) {
		li_MD5_Init(&Md5Ctx);
		/* Errata ID 1649: http://www.rfc-editor.org/errata_search.php?rfc=2617 */
		CvtHex(HA1, &a1);
		li_MD5_Update(&Md5Ctx, (unsigned char *)a1, HASHHEXLEN);
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, (unsigned char *)nonce, strlen(nonce));
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, (unsigned char *)cnonce, strlen(cnonce));
		li_MD5_Final(HA1, &Md5Ctx);
	}

	CvtHex(HA1, &a1);

	/* calculate H(A2) */
	li_MD5_Init(&Md5Ctx);
	li_MD5_Update(&Md5Ctx, (unsigned char *)m, strlen(m));
	li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
	li_MD5_Update(&Md5Ctx, (unsigned char *)uri, strlen(uri));
	/* qop=auth-int not supported, already checked above */
/*
	if (qop && strcasecmp(qop, "auth-int") == 0) {
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, (unsigned char *) [body checksum], HASHHEXLEN);
	}
*/
	li_MD5_Final(HA2, &Md5Ctx);
	CvtHex(HA2, &HA2Hex);

	/* calculate response */
	li_MD5_Init(&Md5Ctx);
	li_MD5_Update(&Md5Ctx, (unsigned char *)a1, HASHHEXLEN);
	li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
	li_MD5_Update(&Md5Ctx, (unsigned char *)nonce, strlen(nonce));
	li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
	if (qop && *qop) {
		li_MD5_Update(&Md5Ctx, (unsigned char *)nc, strlen(nc));
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, (unsigned char *)cnonce, strlen(cnonce));
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
		li_MD5_Update(&Md5Ctx, (unsigned char *)qop, strlen(qop));
		li_MD5_Update(&Md5Ctx, CONST_STR_LEN(":"));
	};
	li_MD5_Update(&Md5Ctx, (unsigned char *)HA2Hex, HASHHEXLEN);
	li_MD5_Final(RespHash, &Md5Ctx);
	CvtHex(RespHash, &a2);

	if (0 != strcmp(a2, respons)) {
		/* digest not ok */

		if (p->conf.auth_debug) {
			log_error_write(srv, __FILE__, __LINE__, "sss",
				"digest: digest mismatch", a2, respons);
		}

		log_error_write(srv, __FILE__, __LINE__, "ssss",
				"digest: auth failed for ", username, ": wrong password, IP:", inet_ntop_cache_get_ip(srv, &(con->dst_addr)));

		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(srv, con, p, req, 0);
	}

	/* value is our allow-rules */
	if (mod_auth_match_rules(srv, req, username, NULL, NULL)) {

		if (p->conf.auth_debug) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"digest: rules did match");
		}

		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(srv, con, p, req, 0);
	}

	/* check age of nonce.  Note that rand() is used in nonce generation
	 * in mod_auth_digest_generate_nonce().  If that were replaced
	 * with nanosecond time, then nonce secret would remain unique enough
	 * for the purposes of Digest auth, and would be reproducible (and
	 * verifiable) if nanoseconds were inclued with seconds as part of the
	 * nonce "timestamp:secret".  Since that is not done, timestamp in
	 * nonce could theoretically be modified and still produce same md5sum,
	 * but that is highly unlikely within a 10 min (moving) window of valid
	 * time relative to current time (now) */
	{
		time_t ts = 0;
		const unsigned char * const nonce_uns = (unsigned char *)nonce;
		for (i = 0; i < 8 && light_isxdigit(nonce_uns[i]); ++i) {
			ts = (ts << 4) + hex2int(nonce_uns[i]);
		}
		if (i != 8 || nonce[8] != ':'
		    || ts > srv->cur_ts || srv->cur_ts - ts > 600) { /*(10 mins)*/
			/* nonce is stale; have client regenerate digest */
			buffer_free(b);
			return mod_auth_send_401_unauthorized_digest(srv, con, p, req, 1);
		} /*(future: might send nextnonce when expiration is imminent)*/
	}

	mod_auth_setenv(srv, con, username, strlen(username), CONST_STR_LEN("Digest"));

	buffer_free(b);

	if (p->conf.auth_debug) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"digest: auth ok");
	}

	return HANDLER_GO_ON;
}

static int mod_auth_digest_generate_nonce(server *srv, mod_auth_plugin_data *p, buffer *fn, char (*out)[33]) {
	HASH h;
	li_MD5_CTX Md5Ctx;
	char hh[LI_ITOSTRING_LENGTH];

	UNUSED(p);

	/* generate shared-secret */
	li_MD5_Init(&Md5Ctx);
	li_MD5_Update(&Md5Ctx, CONST_BUF_LEN(fn));
	li_MD5_Update(&Md5Ctx, CONST_STR_LEN("+"));

	/* we assume sizeof(time_t) == 4 here, but if not it ain't a problem at all */
	li_itostrn(hh, sizeof(hh), srv->cur_ts);
	li_MD5_Update(&Md5Ctx, (unsigned char *)hh, strlen(hh));
	li_MD5_Update(&Md5Ctx, (unsigned char *)srv->entropy, sizeof(srv->entropy));
	li_itostrn(hh, sizeof(hh), rand());
	li_MD5_Update(&Md5Ctx, (unsigned char *)hh, strlen(hh));

	li_MD5_Final(h, &Md5Ctx);

	CvtHex(h, out);

	return 0;
}

static handler_t mod_auth_uri_handler(server *srv, connection *con, void *p_d) {
	size_t k;
	int auth_required;
	char *http_authorization = NULL;
	data_string *ds;
	mod_auth_plugin_data *p = p_d;
	array *req;
	data_string *req_method;

	/* select the right config */
	mod_auth_patch_connection(srv, con, p);

	if (p->conf.auth_require == NULL) return HANDLER_GO_ON;

	/*
	 * AUTH
	 *
	 */

	/* do we have to ask for auth ? */

	auth_required = 0;

	/* search auth-directives for path */
	for (k = 0; k < p->conf.auth_require->used; k++) {
		buffer *require = p->conf.auth_require->data[k]->key;

		if (buffer_is_empty(require)) continue;
		if (buffer_string_length(con->uri.path) < buffer_string_length(require)) continue;

		/* if we have a case-insensitive FS we have to lower-case the URI here too */

		if (con->conf.force_lowercase_filenames) {
			if (0 == strncasecmp(con->uri.path->ptr, require->ptr, buffer_string_length(require))) {
				auth_required = 1;
				break;
			}
		} else {
			if (0 == strncmp(con->uri.path->ptr, require->ptr, buffer_string_length(require))) {
				auth_required = 1;
				break;
			}
		}
	}

	/* nothing to do for us */
	if (auth_required == 0) return HANDLER_GO_ON;

	req = ((data_array *)(p->conf.auth_require->data[k]))->value;
	req_method = (data_string *)array_get_element(req, "method");

	if (0 == strcmp(req_method->value->ptr, "extern")) {
		/* require REMOTE_USER to be already set */
		if (NULL == (ds = (data_string *)array_get_element(con->environment, "REMOTE_USER"))) {
			con->http_status = 401;
			con->mode = DIRECT;
			return HANDLER_FINISHED;
		} else if (mod_auth_match_rules(srv, req, ds->value->ptr, NULL, NULL)) {
			log_error_write(srv, __FILE__, __LINE__, "s", "rules didn't match");
			con->http_status = 401;
			con->mode = DIRECT;
			return HANDLER_FINISHED;
		} else {
			return HANDLER_GO_ON;
		}
	}

	/* check for configured backend
	 * (XXX: should try to catch this at config time, if not "extern" method) */
	if (NULL == p->conf.auth_backend) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "auth.backend not configured for", con->uri.path);
		con->http_status = 500;
		con->mode = DIRECT;
		return HANDLER_FINISHED;
	}

	/* try to get Authorization-header */

	if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Authorization")) && !buffer_is_empty(ds->value)) {
		char *auth_realm;

		http_authorization = ds->value->ptr;

		/* parse auth-header */
		if (NULL != (auth_realm = strchr(http_authorization, ' '))) {
			int auth_type_len = auth_realm - http_authorization;

			if ((auth_type_len == 5) &&
			    (0 == strncasecmp(http_authorization, "Basic", auth_type_len))) {
				if (0 == strcmp(req_method->value->ptr, "basic")) {
					return mod_auth_basic_check(srv, con, p, req, auth_realm+1);
				}
			} else if ((auth_type_len == 6) &&
				   (0 == strncasecmp(http_authorization, "Digest", auth_type_len))) {
				if (0 == strcmp(req_method->value->ptr, "digest")) {
					return mod_auth_digest_check(srv, con, p, req, auth_realm+1);
				}
			} else {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"unknown authentication type:",
						http_authorization);
				return mod_auth_send_400_bad_request(srv, con);
			}
		} else {
			return mod_auth_send_400_bad_request(srv, con);
		}
	}

	if (0 == strcmp(req_method->value->ptr, "basic")) {
		return mod_auth_send_401_unauthorized_basic(srv, con, p, req);
	} else if (0 == strcmp(req_method->value->ptr, "digest")) {
		return mod_auth_send_401_unauthorized_digest(srv, con, p, req, 0);
	} else {
		/* evil */
		con->http_status = 401;
		con->mode = DIRECT;
		return HANDLER_FINISHED;
	}
}

SETDEFAULTS_FUNC(mod_auth_set_defaults) {
	mod_auth_plugin_data *p = p_d;
	size_t i;

	config_values_t cv[] = {
		{ "auth.backend",                   NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "auth.require",                   NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },  /* 1 */
		{ "auth.debug",                     NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },  /* 2 */
		{ NULL,                             NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(1, srv->config_context->used * sizeof(mod_auth_plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		mod_auth_plugin_config *s;
		size_t n;
		data_array *da;

		s = calloc(1, sizeof(mod_auth_plugin_config));
		s->auth_backend_conf = buffer_init();

		s->auth_debug = 0;

		s->auth_require = array_init();

		cv[0].destination = s->auth_backend_conf;
		cv[1].destination = s->auth_require;
		cv[2].destination = &(s->auth_debug);

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (!buffer_string_is_empty(s->auth_backend_conf)) {
			s->auth_backend = http_auth_backend_get(s->auth_backend_conf);
			if (NULL == s->auth_backend) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "auth.backend not supported:", s->auth_backend_conf);

				return HANDLER_ERROR;
			}
		}

		/* no auth.require for this section */
		if (NULL == (da = (data_array *)array_get_element(config->value, "auth.require"))) continue;

		if (da->type != TYPE_ARRAY) continue;

		for (n = 0; n < da->value->used; n++) {
			size_t m;
			data_array *da_file = (data_array *)da->value->data[n];
			const char *method, *realm, *require;

			if (da->value->data[n]->type != TYPE_ARRAY) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"auth.require should contain an array as in:",
						"auth.require = ( \"...\" => ( ..., ...) )");

				return HANDLER_ERROR;
			}

			method = realm = require = NULL;

			for (m = 0; m < da_file->value->used; m++) {
				if (da_file->value->data[m]->type == TYPE_STRING) {
					if (0 == strcmp(da_file->value->data[m]->key->ptr, "method")) {
						method = ((data_string *)(da_file->value->data[m]))->value->ptr;
					} else if (0 == strcmp(da_file->value->data[m]->key->ptr, "realm")) {
						realm = ((data_string *)(da_file->value->data[m]))->value->ptr;
					} else if (0 == strcmp(da_file->value->data[m]->key->ptr, "require")) {
						require = ((data_string *)(da_file->value->data[m]))->value->ptr;
					} else {
						log_error_write(srv, __FILE__, __LINE__, "ssbs",
							"the field is unknown in:",
							"auth.require = ( \"...\" => ( ..., -> \"",
							da_file->value->data[m]->key,
							"\" <- => \"...\" ) )");

						return HANDLER_ERROR;
					}
				} else {
					log_error_write(srv, __FILE__, __LINE__, "ssbs",
						"a string was expected for:",
						"auth.require = ( \"...\" => ( ..., -> \"",
						da_file->value->data[m]->key,
						"\" <- => \"...\" ) )");

					return HANDLER_ERROR;
				}
			}

			if (method == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"the method field is missing in:",
						"auth.require = ( \"...\" => ( ..., \"method\" => \"...\" ) )");
				return HANDLER_ERROR;
			} else {
				if (0 != strcmp(method, "basic") &&
				    0 != strcmp(method, "digest") &&
				    0 != strcmp(method, "extern")) {
					log_error_write(srv, __FILE__, __LINE__, "ss",
							"method has to be either \"basic\", \"digest\" or \"extern\" in",
							"auth.require = ( \"...\" => ( ..., \"method\" => \"...\") )");
					return HANDLER_ERROR;
				}
			}

			if (realm == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"the realm field is missing in:",
						"auth.require = ( \"...\" => ( ..., \"realm\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (require == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"the require field is missing in:",
						"auth.require = ( \"...\" => ( ..., \"require\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (method && realm && require) {
				data_string *ds;
				data_array *a;

				a = data_array_init();
				buffer_copy_buffer(a->key, da_file->key);

				ds = data_string_init();

				buffer_copy_string_len(ds->key, CONST_STR_LEN("method"));
				buffer_copy_string(ds->value, method);

				array_insert_unique(a->value, (data_unset *)ds);

				ds = data_string_init();

				buffer_copy_string_len(ds->key, CONST_STR_LEN("realm"));
				buffer_copy_string(ds->value, realm);

				array_insert_unique(a->value, (data_unset *)ds);

				ds = data_string_init();

				buffer_copy_string_len(ds->key, CONST_STR_LEN("require"));
				buffer_copy_string(ds->value, require);

				array_insert_unique(a->value, (data_unset *)ds);

				array_insert_unique(s->auth_require, (data_unset *)a);
			}
		}
	}

	return HANDLER_GO_ON;
}

int mod_auth_plugin_init(plugin *p);
int mod_auth_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("auth");
	p->init        = mod_auth_init;
	p->set_defaults = mod_auth_set_defaults;
	p->handle_uri_clean = mod_auth_uri_handler;
	p->cleanup     = mod_auth_free;

	p->data        = NULL;

	return 0;
}
