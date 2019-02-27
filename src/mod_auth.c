#include "first.h"

#include "base.h"
#include "plugin.h"
#include "http_auth.h"
#include "http_header.h"
#include "log.h"

#include "sys-crypto.h" /* USE_OPENSSL_CRYPTO */
#ifdef USE_OPENSSL_CRYPTO
#include <openssl/sha.h>
#endif

#include <stdlib.h>
#include <string.h>

/**
 * auth framework
 */

typedef struct {
	/* auth */
	array  *auth_require;
	buffer *auth_backend_conf;
	unsigned short auth_extern_authn;

	/* generated */
	const http_auth_backend_t *auth_backend;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

static handler_t mod_auth_check_basic(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);
static handler_t mod_auth_check_digest(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);
static handler_t mod_auth_check_extern(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);

INIT_FUNC(mod_auth_init) {
	static const http_auth_scheme_t http_auth_scheme_basic  = { "basic",  mod_auth_check_basic,  NULL };
	static const http_auth_scheme_t http_auth_scheme_digest = { "digest", mod_auth_check_digest, NULL };
	static const http_auth_scheme_t http_auth_scheme_extern = { "extern", mod_auth_check_extern, NULL };
	plugin_data *p;

	/* register http_auth_scheme_* */
	http_auth_scheme_set(&http_auth_scheme_basic);
	http_auth_scheme_set(&http_auth_scheme_digest);
	http_auth_scheme_set(&http_auth_scheme_extern);

	p = calloc(1, sizeof(*p));

	return p;
}

FREE_FUNC(mod_auth_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

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

/* data type for mod_auth structured data
 * (parsed from auth.require array of strings) */
typedef struct {
    DATA_UNSET;
    http_auth_require_t *require;
} data_auth;

static void data_auth_free(data_unset *d)
{
    data_auth * const dauth = (data_auth *)d;
    buffer_free(dauth->key);
    http_auth_require_free(dauth->require);
    free(dauth);
}

static data_auth *data_auth_init(void)
{
    static const struct data_methods fn = {
      NULL, /* reset must not be called on this data */
      NULL, /* copy must not be called on this data */
      data_auth_free,
      NULL, /* insert_dup must not be called on this data */
      NULL  /* print must not be called on this data */
    };
    data_auth * const dauth = calloc(1, sizeof(*dauth));
    force_assert(NULL != dauth);
    dauth->type       = TYPE_OTHER;
    dauth->fn         = &fn;

    dauth->key = buffer_init();
    dauth->require = http_auth_require_init();

    return dauth;
}

static int mod_auth_algorithm_parse(http_auth_info_t *ai, const char *s) {
    size_t len;
    if (NULL == s) {
        ai->dalgo = HTTP_AUTH_DIGEST_MD5;
        ai->dlen  = HTTP_AUTH_DIGEST_MD5_BINLEN;
        return 1;
    }

    len = strlen(s);
    if (len > 5
        && (s[len-5]       ) == '-'
        && (s[len-4] | 0x20) == 's'
        && (s[len-3] | 0x20) == 'e'
        && (s[len-2] | 0x20) == 's'
        && (s[len-1] | 0x20) == 's') {
        ai->dalgo = HTTP_AUTH_DIGEST_SESS;
        len -= 5;
    }
    else {
        ai->dalgo = HTTP_AUTH_DIGEST_NONE;
    }

    if (3 == len
        && 'm' == (s[0] | 0x20)
        && 'd' == (s[1] | 0x20)
        && '5' == (s[2]       )) {
        ai->dalgo |= HTTP_AUTH_DIGEST_MD5;
        ai->dlen   = HTTP_AUTH_DIGEST_MD5_BINLEN;
        return 1;
    }
  #ifdef USE_OPENSSL_CRYPTO
    else if (len >= 7
             && 's' == (s[0] | 0x20)
             && 'h' == (s[1] | 0x20)
             && 'a' == (s[2] | 0x20)
             && '-' == (s[3]       )) {
        if (len == 7 && s[4] == '2' && s[5] == '5' && s[6] == '6') {
            ai->dalgo |= HTTP_AUTH_DIGEST_SHA256;
            ai->dlen   = HTTP_AUTH_DIGEST_SHA256_BINLEN;
            return 1;
        }
      #ifdef SHA512_256_DIGEST_LENGTH
        if (len == 11 && 0 == memcmp(s+4, "512-256", 7)) {
            ai->dalgo |= HTTP_AUTH_DIGEST_SHA512_256;
            ai->dlen   = HTTP_AUTH_DIGEST_SHA512_256_BINLEN;
            return 1;
        }
      #endif
    }
  #endif
    return 0; /*(error)*/
}

static int mod_auth_algorithms_parse(int *algorithm, buffer *algos) {
    for (char *s = algos->ptr, *p; s; s = p ? p+1 : NULL) {
        http_auth_info_t ai;
        int rc;
        p = strchr(s, '|');
        if (p) *p = '\0';
        rc = mod_auth_algorithm_parse(&ai, s);
        if (p) *p = '|';
        if (!rc) return 0;
        *algorithm |= ai.dalgo;
    }
    return 1;
}

static int mod_auth_require_parse (server *srv, http_auth_require_t * const require, const buffer *b)
{
    /* user=name1|user=name2|group=name3|host=name4 */

    const char *str = b->ptr;
    const char *p;

    if (buffer_is_equal_string(b, CONST_STR_LEN("valid-user"))) {
        require->valid_user = 1;
        return 1; /* success */
    }

    do {
        const char *eq;
        size_t len;
        p = strchr(str, '|');
        len = NULL != p ? (size_t)(p - str) : strlen(str);
        eq = memchr(str, '=', len);
        if (NULL == eq) {
            log_error_write(srv, __FILE__, __LINE__, "sssbss",
                            "error parsing auth.require 'require' field: missing '='",
                            "(expecting \"valid-user\" or \"user=a|user=b|group=g|host=h\").",
                            "error value:", b, "error near:", str);
            return 0;
        }
        if (eq[1] == '|' || eq[1] == '\0') {
            log_error_write(srv, __FILE__, __LINE__, "sssbss",
                            "error parsing auth.require 'require' field: missing token after '='",
                            "(expecting \"valid-user\" or \"user=a|user=b|group=g|host=h\").",
                            "error value:", b, "error near:", str);
            return 0;
        }

        switch ((int)(eq - str)) {
          case 4:
            if (0 == memcmp(str, CONST_STR_LEN("user"))) {
                /*("user=" is 5)*/
                array_set_key_value(require->user, str+5, len-5, CONST_STR_LEN(""));
                continue;
            }
            else if (0 == memcmp(str, CONST_STR_LEN("host"))) {
                /*("host=" is 5)*/
                array_set_key_value(require->host, str+5, len-5, CONST_STR_LEN(""));
                log_error_write(srv, __FILE__, __LINE__, "ssb",
                                "warning parsing auth.require 'require' field: 'host' not implemented;",
                                "field value:", b);
                continue;
            }
            break; /* to error */
          case 5:
            if (0 == memcmp(str, CONST_STR_LEN("group"))) {
                /*("group=" is 6)*/
                array_set_key_value(require->group, str+6, len-6, CONST_STR_LEN(""));
              #if 0/*(supported by mod_authn_ldap, but not all other backends)*/
                log_error_write(srv, __FILE__, __LINE__, "ssb",
                                "warning parsing auth.require 'require' field: 'group' not implemented;",
                                "field value:", b);
              #endif
                continue;
            }
            break; /* to error */
          case 10:
            if (0 == memcmp(str, CONST_STR_LEN("valid-user"))) {
                log_error_write(srv, __FILE__, __LINE__, "sssb",
                                "error parsing auth.require 'require' field: valid user can not be combined with other require rules",
                                "(expecting \"valid-user\" or \"user=a|user=b|group=g|host=h\").",
                                "error value:", b);
                return 0;
            }
            break; /* to error */
          default:
            break; /* to error */
        }

        log_error_write(srv, __FILE__, __LINE__, "sssbss",
                        "error parsing auth.require 'require' field: invalid/unsupported token",
                        "(expecting \"valid-user\" or \"user=a|user=b|group=g|host=h\").",
                        "error value:", b, "error near:", str);
        return 0;

    } while (p && *((str = p+1)));

    return 1; /* success */
}

SETDEFAULTS_FUNC(mod_auth_set_defaults) {
	plugin_data *p = p_d;
	size_t i;

	config_values_t cv[] = {
		{ "auth.backend",                   NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "auth.require",                   NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },  /* 1 */
		{ "auth.extern-authn",              NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },/* 2 */
		{ NULL,                             NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;
		size_t n;
		data_array *da;

		s = calloc(1, sizeof(plugin_config));
		s->auth_backend_conf = buffer_init();

		s->auth_require = array_init();

		cv[0].destination = s->auth_backend_conf;
		cv[1].destination = s->auth_require; /* T_CONFIG_LOCAL; not modified by config_insert_values_global() */
		cv[2].destination = &s->auth_extern_authn;

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

		if (da->type != TYPE_ARRAY || !array_is_kvarray(da->value)) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"unexpected value for auth.require; expected ",
					"auth.require = ( \"urlpath\" => ( \"option\" => \"value\" ) )");
			return HANDLER_ERROR;
		}


		for (n = 0; n < da->value->used; n++) {
			size_t m;
			data_array *da_file = (data_array *)da->value->data[n];
			const buffer *method = NULL, *realm = NULL, *require = NULL;
			const http_auth_scheme_t *auth_scheme;
			buffer *algos = NULL;
			int algorithm = HTTP_AUTH_DIGEST_SESS;

			if (!array_is_kvstring(da_file->value)) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"unexpected value for auth.require; expected ",
						"auth.require = ( \"urlpath\" => ( \"option\" => \"value\" ) )");

				return HANDLER_ERROR;
			}

			for (m = 0; m < da_file->value->used; m++) {
				if (da_file->value->data[m]->type == TYPE_STRING) {
					data_string *ds = (data_string *)da_file->value->data[m];
					if (buffer_is_equal_string(ds->key, CONST_STR_LEN("method"))) {
						method = ds->value;
					} else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("realm"))) {
						realm = ds->value;
					} else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("require"))) {
						require = ds->value;
					} else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("algorithm"))) {
						algos = ds->value;
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

			if (buffer_string_is_empty(method)) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"the method field is missing or blank in:",
						"auth.require = ( \"...\" => ( ..., \"method\" => \"...\" ) )");
				return HANDLER_ERROR;
			} else {
				auth_scheme = http_auth_scheme_get(method);
				if (NULL == auth_scheme) {
					log_error_write(srv, __FILE__, __LINE__, "sbss",
							"unknown method", method, "(e.g. \"basic\", \"digest\" or \"extern\") in",
							"auth.require = ( \"...\" => ( ..., \"method\" => \"...\") )");
					return HANDLER_ERROR;
				}
			}

			if (buffer_is_empty(realm)) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"the realm field is missing in:",
						"auth.require = ( \"...\" => ( ..., \"realm\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (buffer_string_is_empty(require)) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"the require field is missing or blank in:",
						"auth.require = ( \"...\" => ( ..., \"require\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (buffer_string_is_empty(algos)) {
				algorithm |= HTTP_AUTH_DIGEST_MD5;
			} else if (!mod_auth_algorithms_parse(&algorithm, algos)) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"invalid algorithm in:",
						"auth.require = ( \"...\" => ( ..., \"algorithm\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (require) { /*(always true at this point)*/
				data_auth * const dauth = data_auth_init();
				buffer_copy_buffer(dauth->key, da_file->key);
				dauth->require->scheme = auth_scheme;
				dauth->require->algorithm = algorithm;
				buffer_copy_buffer(dauth->require->realm, realm);
				if (!mod_auth_require_parse(srv, dauth->require, require)) {
					dauth->fn->free((data_unset *)dauth);
					return HANDLER_ERROR;
				}
				array_insert_unique(s->auth_require, (data_unset *)dauth);
			}
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_auth_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(auth_backend);
	PATCH(auth_require);
	PATCH(auth_extern_authn);

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
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.extern-authn"))) {
				PATCH(auth_extern_authn);
			}
		}
	}

	return 0;
}
#undef PATCH

static handler_t mod_auth_uri_handler(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	data_auth *dauth;

	mod_auth_patch_connection(srv, con, p);

	if (p->conf.auth_require == NULL) return HANDLER_GO_ON;

	/* search auth directives for first prefix match against URL path */
	/* if we have a case-insensitive FS we have to lower-case the URI here too */
	dauth = (!con->conf.force_lowercase_filenames)
	   ? (data_auth *)array_match_key_prefix(p->conf.auth_require, con->uri.path)
	   : (data_auth *)array_match_key_prefix_nc(p->conf.auth_require, con->uri.path);
	if (NULL == dauth) return HANDLER_GO_ON;

	{
			const http_auth_scheme_t * const scheme = dauth->require->scheme;
			if (p->conf.auth_extern_authn) {
				buffer *vb = http_header_env_get(con, CONST_STR_LEN("REMOTE_USER"));
				if (NULL != vb && http_auth_match_rules(dauth->require, vb->ptr, NULL, NULL)) {
					return HANDLER_GO_ON;
				}
			}
			return scheme->checkfn(srv, con, scheme->p_d, dauth->require, p->conf.auth_backend);
	}
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




/*
 * auth schemes (basic, digest, extern)
 *
 * (could be in separate file from mod_auth.c as long as registration occurs)
 */

#include "base64.h"
#include "md5.h"
#include "rand.h"
#include "http_header.h"

static handler_t mod_auth_send_400_bad_request(server *srv, connection *con) {
	UNUSED(srv);

	/* a field was missing or invalid */
	con->http_status = 400; /* Bad Request */
	con->mode = DIRECT;

	return HANDLER_FINISHED;
}

static handler_t mod_auth_send_401_unauthorized_basic(server *srv, connection *con, buffer *realm) {
	con->http_status = 401;
	con->mode = DIRECT;

	buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("Basic realm=\""));
	buffer_append_string_buffer(srv->tmp_buf, realm);
	buffer_append_string_len(srv->tmp_buf, CONST_STR_LEN("\", charset=\"UTF-8\""));

	http_header_response_set(con, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(srv->tmp_buf));

	return HANDLER_FINISHED;
}

static handler_t mod_auth_check_basic(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend) {
	buffer *b = http_header_request_get(con, HTTP_HEADER_AUTHORIZATION, CONST_STR_LEN("Authorization"));
	buffer *username;
	char *pw;
	handler_t rc = HANDLER_UNSET;

	UNUSED(p_d);

	if (NULL == backend) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "auth.backend not configured for", con->uri.path);
		con->http_status = 500;
		con->mode = DIRECT;
		return HANDLER_FINISHED;
	}

	if (NULL == b) {
		return mod_auth_send_401_unauthorized_basic(srv, con, require->realm);
	}

	if (0 != strncasecmp(b->ptr, "Basic ", sizeof("Basic ")-1)) {
		return mod_auth_send_401_unauthorized_basic(srv, con, require->realm);
	}
      #ifdef __COVERITY__
	if (buffer_string_length(b) < sizeof("Basic ")-1) {
		return mod_auth_send_400_bad_request(srv, con);
	}
      #endif

	username = buffer_init();

	/* coverity[overflow_sink : FALSE] */
	if (!buffer_append_base64_decode(username, b->ptr+sizeof("Basic ")-1, buffer_string_length(b)-(sizeof("Basic ")-1), BASE64_STANDARD)) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "decoding base64-string failed", username);

		buffer_free(username);
		return mod_auth_send_400_bad_request(srv, con);
	}

	/* r2 == user:password */
	if (NULL == (pw = strchr(username->ptr, ':'))) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "missing ':' in", username);

		buffer_free(username);
		return mod_auth_send_400_bad_request(srv, con);
	}

	buffer_string_set_length(username, pw - username->ptr);
	pw++;

	rc = backend->basic(srv, con, backend->p_d, require, username, pw);
	switch (rc) {
	case HANDLER_GO_ON:
		http_auth_setenv(con, CONST_BUF_LEN(username), CONST_STR_LEN("Basic"));
		break;
	case HANDLER_WAIT_FOR_EVENT:
	case HANDLER_FINISHED:
		break;
	case HANDLER_ERROR:
	default:
		log_error_write(srv, __FILE__, __LINE__, "sbsBsB", "password doesn't match for", con->uri.path, "username:", username, ", IP:", con->dst_addr_buf);
		rc = HANDLER_UNSET;
		break;
	}

	buffer_free(username);
	return (HANDLER_UNSET != rc) ? rc : mod_auth_send_401_unauthorized_basic(srv, con, require->realm);
}


#ifdef USE_OPENSSL_CRYPTO

static void mod_auth_digest_mutate_sha256(http_auth_info_t *ai, const char *m, const char *uri, const char *nonce, const char *cnonce, const char *nc, const char *qop) {
    SHA256_CTX ctx;
    char a1[HTTP_AUTH_DIGEST_SHA256_BINLEN*2+1];
    char a2[HTTP_AUTH_DIGEST_SHA256_BINLEN*2+1];

    if (ai->dalgo & HTTP_AUTH_DIGEST_SESS) {
        SHA256_Init(&ctx);
        li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);
        SHA256_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        SHA256_Final(ai->digest, &ctx);
    }

    li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);

    /* calculate H(A2) */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char *)m, strlen(m));
    SHA256_Update(&ctx, CONST_STR_LEN(":"));
    SHA256_Update(&ctx, (unsigned char *)uri, strlen(uri));
  #if 0
    /* qop=auth-int not supported, already checked in caller */
    if (qop && strcasecmp(qop, "auth-int") == 0) {
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *) [body checksum], ai->dlen*2);
    }
  #endif
    SHA256_Final(ai->digest, &ctx);
    li_tohex(a2, sizeof(a2), (const char *)ai->digest, ai->dlen);

    /* calculate response */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
    SHA256_Update(&ctx, CONST_STR_LEN(":"));
    SHA256_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
    SHA256_Update(&ctx, CONST_STR_LEN(":"));
    if (qop && *qop) {
        SHA256_Update(&ctx, (unsigned char *)nc, strlen(nc));
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *)qop, strlen(qop));
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
    }
    SHA256_Update(&ctx, (unsigned char *)a2, sizeof(a2)-1);
    SHA256_Final(ai->digest, &ctx);
}

static void mod_auth_digest_nonce_sha256(buffer *b, time_t cur_ts, int rnd) {
    SHA256_CTX ctx;
    unsigned char h[HTTP_AUTH_DIGEST_SHA256_BINLEN];
    char hh[HTTP_AUTH_DIGEST_SHA256_BINLEN*2+1];
    force_assert(sizeof(hh) >= LI_ITOSTRING_LENGTH);
    SHA256_Init(&ctx);
    li_itostrn(hh, sizeof(hh), cur_ts);
    SHA256_Update(&ctx, (unsigned char *)hh, strlen(hh));
    li_itostrn(hh, sizeof(hh), rnd);
    SHA256_Update(&ctx, (unsigned char *)hh, strlen(hh));
    SHA256_Final(h, &ctx);
    li_tohex(hh, sizeof(hh), (const char *)h, sizeof(h));
    buffer_append_string_len(b, hh, sizeof(hh)-1);
}

#ifdef SHA512_256_DIGEST_LENGTH

static void mod_auth_digest_mutate_sha512_256(http_auth_info_t *ai, const char *m, const char *uri, const char *nonce, const char *cnonce, const char *nc, const char *qop) {
    SHA512_CTX ctx;
    char a1[HTTP_AUTH_DIGEST_SHA512_256_BINLEN*2+1];
    char a2[HTTP_AUTH_DIGEST_SHA512_256_BINLEN*2+1];

    if (ai->dalgo & HTTP_AUTH_DIGEST_SESS) {
        SHA512_256_Init(&ctx);
        li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);
        SHA512_256_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        SHA512_256_Final(ai->digest, &ctx);
    }

    li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);

    /* calculate H(A2) */
    SHA512_256_Init(&ctx);
    SHA512_256_Update(&ctx, (unsigned char *)m, strlen(m));
    SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    SHA512_256_Update(&ctx, (unsigned char *)uri, strlen(uri));
  #if 0
    /* qop=auth-int not supported, already checked in caller */
    if (qop && strcasecmp(qop, "auth-int") == 0) {
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)[body checksum], ai->dlen*2);
    }
  #endif
    SHA512_256_Final(ai->digest, &ctx);
    li_tohex(a2, sizeof(a2), (const char *)ai->digest, ai->dlen);

    /* calculate response */
    SHA512_256_Init(&ctx);
    SHA512_256_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
    SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    SHA512_256_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
    SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    if (qop && *qop) {
        SHA512_256_Update(&ctx, (unsigned char *)nc, strlen(nc));
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)qop, strlen(qop));
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    }
    SHA512_256_Update(&ctx, (unsigned char *)a2, sizeof(a2)-1);
    SHA512_256_Final(ai->digest, &ctx);
}

static void mod_auth_digest_nonce_sha512_256(buffer *b, time_t cur_ts, int rnd) {
    SHA512_CTX ctx;
    unsigned char h[HTTP_AUTH_DIGEST_SHA512_256_BINLEN];
    char hh[HTTP_AUTH_DIGEST_SHA512_256_BINLEN*2+1];
    force_assert(sizeof(hh) >= LI_ITOSTRING_LENGTH);
    SHA512_256_Init(&ctx);
    li_itostrn(hh, sizeof(hh), cur_ts);
    SHA512_256_Update(&ctx, (unsigned char *)hh, strlen(hh));
    li_itostrn(hh, sizeof(hh), rnd);
    SHA512_256_Update(&ctx, (unsigned char *)hh, strlen(hh));
    SHA512_256_Final(h, &ctx);
    li_tohex(hh, sizeof(hh), (const char *)h, sizeof(h));
    buffer_append_string_len(b, hh, sizeof(hh)-1);
}

#endif /* SHA512_256_DIGEST_LENGTH */

#endif /* USE_OPENSSL_CRYPTO */

static void mod_auth_digest_mutate_md5(http_auth_info_t *ai, const char *m, const char *uri, const char *nonce, const char *cnonce, const char *nc, const char *qop) {
    li_MD5_CTX ctx;
    char a1[HTTP_AUTH_DIGEST_MD5_BINLEN*2+1];
    char a2[HTTP_AUTH_DIGEST_MD5_BINLEN*2+1];

    if (ai->dalgo & HTTP_AUTH_DIGEST_SESS) {
        li_MD5_Init(&ctx);
        /* http://www.rfc-editor.org/errata_search.php?rfc=2617
         * Errata ID: 1649 */
        li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);
        li_MD5_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        li_MD5_Final(ai->digest, &ctx);
    }

    li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);

    /* calculate H(A2) */
    li_MD5_Init(&ctx);
    li_MD5_Update(&ctx, (unsigned char *)m, strlen(m));
    li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    li_MD5_Update(&ctx, (unsigned char *)uri, strlen(uri));
  #if 0
    /* qop=auth-int not supported, already checked in caller */
    if (qop && strcasecmp(qop, "auth-int") == 0) {
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *) [body checksum], ai->dlen*2);
    }
  #endif
    li_MD5_Final(ai->digest, &ctx);
    li_tohex(a2, sizeof(a2), (const char *)ai->digest, ai->dlen);

    /* calculate response */
    li_MD5_Init(&ctx);
    li_MD5_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
    li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    li_MD5_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
    li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    if (qop && *qop) {
        li_MD5_Update(&ctx, (unsigned char *)nc, strlen(nc));
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *)qop, strlen(qop));
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    }
    li_MD5_Update(&ctx, (unsigned char *)a2, sizeof(a2)-1);
    li_MD5_Final(ai->digest, &ctx);
}

static void mod_auth_digest_nonce_md5(buffer *b, time_t cur_ts, int rnd) {
    li_MD5_CTX ctx;
    unsigned char h[HTTP_AUTH_DIGEST_MD5_BINLEN];
    char hh[HTTP_AUTH_DIGEST_MD5_BINLEN*2+1];
    force_assert(sizeof(hh) >= LI_ITOSTRING_LENGTH);
    li_MD5_Init(&ctx);
    li_itostrn(hh, sizeof(hh), cur_ts);
    li_MD5_Update(&ctx, (unsigned char *)hh, strlen(hh));
    li_itostrn(hh, sizeof(hh), rnd);
    li_MD5_Update(&ctx, (unsigned char *)hh, strlen(hh));
    li_MD5_Final(h, &ctx);
    li_tohex(hh, sizeof(hh), (const char *)h, sizeof(h));
    buffer_append_string_len(b, hh, sizeof(hh)-1);
}

static void mod_auth_digest_mutate(http_auth_info_t *ai, const char *m, const char *uri, const char *nonce, const char *cnonce, const char *nc, const char *qop) {
    if (ai->dalgo & HTTP_AUTH_DIGEST_MD5)
        mod_auth_digest_mutate_md5(ai, m, uri, nonce, cnonce, nc, qop);
  #ifdef USE_OPENSSL_CRYPTO
    else if (ai->dalgo & HTTP_AUTH_DIGEST_SHA256)
        mod_auth_digest_mutate_sha256(ai, m, uri, nonce, cnonce, nc, qop);
   #ifdef SHA512_256_DIGEST_LENGTH
    else if (ai->dalgo & HTTP_AUTH_DIGEST_SHA512_256)
        mod_auth_digest_mutate_sha512_256(ai, m, uri, nonce, cnonce, nc, qop);
   #endif
  #endif
}

static void mod_auth_digest_www_authenticate(buffer *b, time_t cur_ts, const struct http_auth_require_t *require, int nonce_stale) {
    const int rnd = li_rand_pseudo();
    int algos = nonce_stale ? nonce_stale : require->algorithm;
    int n = 0;
    void(*append_nonce[3])(buffer *, time_t, int);
    unsigned int algolen[3];
    const char *algoname[3];
  #ifdef USE_OPENSSL_CRYPTO
   #ifdef SHA512_256_DIGEST_LENGTH
    if (algos & HTTP_AUTH_DIGEST_SHA512_256) {
        append_nonce[n] = mod_auth_digest_nonce_sha512_256;
        algoname[n] = "SHA-512-256";
        algolen[n] = sizeof("SHA-512-256")-1;
        ++n;
    }
   #endif
    if (algos & HTTP_AUTH_DIGEST_SHA256) {
        append_nonce[n] = mod_auth_digest_nonce_sha256;
        algoname[n] = "SHA-256";
        algolen[n] = sizeof("SHA-256")-1;
        ++n;
    }
  #endif
    if (algos & HTTP_AUTH_DIGEST_MD5) {
        append_nonce[n] = mod_auth_digest_nonce_md5;
        algoname[n] = "MD5";
        algolen[n] = sizeof("MD5")-1;
        ++n;
    }

    buffer_clear(b);
    for (int i = 0; i < n; ++i) {
        if (i > 0) {
            buffer_append_string_len(b,CONST_STR_LEN("\r\nWWW-Authenticate: "));
        }
        buffer_append_string_len(b, CONST_STR_LEN("Digest realm=\""));
        buffer_append_string_buffer(b, require->realm);
        buffer_append_string_len(b, CONST_STR_LEN("\", charset=\"UTF-8\", algorithm=\""));
        buffer_append_string_len(b, algoname[i], algolen[i]);
        buffer_append_string_len(b, CONST_STR_LEN("\", nonce=\""));
        buffer_append_uint_hex(b, (uintmax_t)cur_ts);
        buffer_append_string_len(b, CONST_STR_LEN(":"));
        (append_nonce[i])(b, cur_ts, rnd);
        buffer_append_string_len(b, CONST_STR_LEN("\", qop=\"auth\""));
        if (nonce_stale) {
            buffer_append_string_len(b, CONST_STR_LEN(", stale=true"));
        }
    }
}

typedef struct {
	const char *key;
	int key_len;
	char **ptr;
} digest_kv;

static handler_t mod_auth_send_401_unauthorized_digest(server *srv, connection *con, const struct http_auth_require_t *require, int nonce_stale);

static handler_t mod_auth_check_digest(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend) {
	buffer *vb = http_header_request_get(con, HTTP_HEADER_AUTHORIZATION, CONST_STR_LEN("Authorization"));

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
	http_auth_info_t ai;
	unsigned char rdigest[HTTP_AUTH_DIGEST_SHA256_BINLEN];


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

	UNUSED(p_d);

	if (NULL == backend) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "auth.backend not configured for", con->uri.path);
		con->http_status = 500;
		con->mode = DIRECT;
		return HANDLER_FINISHED;
	}

	if (NULL == vb) {
		return mod_auth_send_401_unauthorized_digest(srv, con, require, 0);
	}

	if (0 != strncasecmp(vb->ptr, "Digest ", sizeof("Digest ")-1)) {
		return mod_auth_send_401_unauthorized_digest(srv, con, require, 0);
	} else {
		size_t n = buffer_string_length(vb);
	      #ifdef __COVERITY__
		if (n < sizeof("Digest ")-1) {
			return mod_auth_send_400_bad_request(srv, con);
		}
	      #endif
		n -= (sizeof("Digest ")-1);
		b = buffer_init();
		buffer_copy_string_len(b,vb->ptr+sizeof("Digest ")-1,n);
	}

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

	ai.username = username;
	ai.ulen     = strlen(username);
	ai.realm    = realm;
	ai.rlen     = strlen(realm);

	if (!buffer_is_equal_string(require->realm, ai.realm, ai.rlen)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"digest: realm mismatch");
		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(srv, con, require, 0);
	}

	if (!mod_auth_algorithm_parse(&ai, algorithm)
	    || !(require->algorithm & ai.dalgo & ~HTTP_AUTH_DIGEST_SESS)) {
		log_error_write(srv, __FILE__, __LINE__, "SSS",
				"digest: (", algorithm, "): invalid");
		buffer_free(b);
		return mod_auth_send_400_bad_request(srv, con);
	}

	/**
	 * protect the md5-sess against missing cnonce and nonce
	 */
	if ((ai.dalgo & HTTP_AUTH_DIGEST_SESS) && (!nonce || !cnonce)) {
		log_error_write(srv, __FILE__, __LINE__, "SSS",
				"digest: (", algorithm, "): missing field");

		buffer_free(b);
		return mod_auth_send_400_bad_request(srv, con);
	}

	{
		size_t resplen = strlen(respons);
		if (0 != http_auth_digest_hex2bin(respons, resplen,
						  rdigest, sizeof(rdigest))
		    || resplen != (ai.dlen << 1)) {
			log_error_write(srv, __FILE__, __LINE__, "SSS",
					"digest: (", respons, "): invalid format");
			buffer_free(b);
			return mod_auth_send_400_bad_request(srv, con);
		}
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
			log_error_write(srv, __FILE__, __LINE__, "sbsssB",
					"digest: auth failed: uri mismatch (", con->request.orig_uri, "!=", uri, "), IP:", con->dst_addr_buf);
			buffer_free(b);
			return mod_auth_send_400_bad_request(srv, con);
		}
	}

	switch (backend->digest(srv, con, backend->p_d, &ai)) {
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
		return mod_auth_send_401_unauthorized_digest(srv, con, require, 0);
	}

	mod_auth_digest_mutate(&ai,m,uri,nonce,cnonce,nc,qop);

	if (0 != memcmp(rdigest, ai.digest, ai.dlen)) {
		/* digest not ok */
		log_error_write(srv, __FILE__, __LINE__, "sssB",
				"digest: auth failed for ", username, ": wrong password, IP:", con->dst_addr_buf);

		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(srv, con, require, 0);
	}

	/* value is our allow-rules */
	if (!http_auth_match_rules(require, username, NULL, NULL)) {
		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(srv, con, require, 0);
	}

	/* check age of nonce.  Note, random data is used in nonce generation
	 * in mod_auth_send_401_unauthorized_digest().  If that were replaced
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
		if (nonce[i] != ':'
		    || ts > srv->cur_ts || srv->cur_ts - ts > 600) { /*(10 mins)*/
			/* nonce is stale; have client regenerate digest */
			buffer_free(b);
			return mod_auth_send_401_unauthorized_digest(srv, con, require, ai.dalgo);
		} /*(future: might send nextnonce when expiration is imminent)*/
	}

	http_auth_setenv(con, ai.username, ai.ulen, CONST_STR_LEN("Digest"));

	buffer_free(b);

	return HANDLER_GO_ON;
}

static handler_t mod_auth_send_401_unauthorized_digest(server *srv, connection *con, const struct http_auth_require_t *require, int nonce_stale) {
	mod_auth_digest_www_authenticate(srv->tmp_buf, srv->cur_ts, require, nonce_stale);
	http_header_response_set(con, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(srv->tmp_buf));

	con->http_status = 401;
	con->mode = DIRECT;
	return HANDLER_FINISHED;
}

static handler_t mod_auth_check_extern(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend) {
	/* require REMOTE_USER already set */
	buffer *vb = http_header_env_get(con, CONST_STR_LEN("REMOTE_USER"));
	UNUSED(srv);
	UNUSED(p_d);
	UNUSED(backend);
	if (NULL != vb && http_auth_match_rules(require, vb->ptr, NULL, NULL)) {
		return HANDLER_GO_ON;
	} else {
		con->http_status = 401;
		con->mode = DIRECT;
		return HANDLER_FINISHED;
	}
}
