#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "base64.h"
#include "http_auth.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

#include "sys-crypto.h"
#ifdef USE_LIB_CRYPTO
#if defined(USE_NETTLE_CRYPTO)
#include <nettle/hmac.h>
#elif defined(USE_OPENSSL_CRYPTO)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif
#endif

#include "md5.h"

/*
 * mod_secdownload verifies a checksum associated with a timestamp
 * and a path.
 *
 * It takes an URL of the form:
 *   securl := <uri-prefix> <mac> <protected-path>
 *   uri-prefix := '/' any*         # whatever was configured: must start with a '/')
 *   mac := [a-zA-Z0-9_-]{mac_len}  # mac length depends on selected algorithm
 *   protected-path := '/' <timestamp> <rel-path>
 *   timestamp := [a-f0-9]{8}       # timestamp when the checksum was calculated
 *                                  # to prevent access after timeout (active requests
 *                                  # will finish successfully even after the timeout)
 *   rel-path := '/' any*           # the protected path; changing the path breaks the
 *                                  # checksum
 *
 * The timestamp is the `epoch` timestamp in hex, i.e. time in seconds
 * since 00:00:00 UTC on 1 January 1970.
 *
 * mod_secdownload supports various MAC algorithms:
 *
 * # md5
 * mac_len := 32 (and hex only)
 * mac := md5-hex(<secrect><rel-path><timestamp>)   # lowercase hex
 * perl example:
    use Digest::MD5 qw(md5_hex);
    my $secret = "verysecret";
    my $rel_path = "/index.html"
    my $xtime = sprintf("%08x", time);
    my $url = '/'. md5_hex($secret . $rel_path . $xtime) . '/' . $xtime . $rel_path;
 *
 * # hmac-sha1
 * mac_len := 27  (no base64 padding)
 * mac := base64-url(hmac-sha1(<secret>, <protected-path>))
 * perl example:
    use Digest::SHA qw(hmac_sha1);
    use MIME::Base64 qw(encode_base64url);
    my $secret = "verysecret";
    my $rel_path = "/index.html"
    my $protected_path = '/' . sprintf("%08x", time) . $rel_path;
    my $url = '/'. encode_base64url(hmac_sha1($protected_path, $secret)) . $protected_path;
 *
 * # hmac-256
 * mac_len := 43  (no base64 padding)
 * mac := base64-url(hmac-256(<secret>, <protected-path>))
    use Digest::SHA qw(hmac_sha256);
    use MIME::Base64 qw(encode_base64url);
    my $secret = "verysecret";
    my $rel_path = "/index.html"
    my $protected_path = '/' . sprintf("%08x", time) . $rel_path;
    my $url = '/'. encode_base64url(hmac_sha256($protected_path, $secret)) . $protected_path;
 *
 */

/* plugin config for all request/connections */

typedef enum {
	SECDL_INVALID = 0,
	SECDL_MD5 = 1,
	SECDL_HMAC_SHA1 = 2,
	SECDL_HMAC_SHA256 = 3,
} secdl_algorithm;

typedef struct {
    const buffer *doc_root;
    const buffer *secret;
    const buffer *uri_prefix;
    secdl_algorithm algorithm;

    unsigned int timeout;
    unsigned short path_segments;
    unsigned short hash_querystr;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

static int const_time_memeq(const char *a, const char *b, size_t len) {
	/* constant time memory compare, unless the compiler figures it out */
	char diff = 0;
	size_t i;
	for (i = 0; i < len; ++i) {
		diff |= (a[i] ^ b[i]);
	}
	return 0 == diff;
}

static const char* secdl_algorithm_names[] = {
	"invalid",
	"md5",
	"hmac-sha1",
	"hmac-sha256",
};

static secdl_algorithm algorithm_from_string(const buffer *name) {
	size_t ndx;

	if (buffer_string_is_empty(name)) return SECDL_INVALID;

	for (ndx = 1; ndx < sizeof(secdl_algorithm_names)/sizeof(secdl_algorithm_names[0]); ++ndx) {
		if (0 == strcmp(secdl_algorithm_names[ndx], name->ptr)) return (secdl_algorithm)ndx;
	}

	return SECDL_INVALID;
}

static size_t secdl_algorithm_mac_length(secdl_algorithm alg) {
	switch (alg) {
	case SECDL_INVALID:
		break;
	case SECDL_MD5:
		return 32;
	case SECDL_HMAC_SHA1:
		return 27;
	case SECDL_HMAC_SHA256:
		return 43;
	}
	return 0;
}

static int secdl_verify_mac(plugin_config *config, const char* protected_path, const char* mac, size_t maclen, log_error_st *errh) {
	UNUSED(errh);
	if (0 == maclen || secdl_algorithm_mac_length(config->algorithm) != maclen) return 0;

	switch (config->algorithm) {
	case SECDL_INVALID:
		break;
	case SECDL_MD5:
		{
			li_MD5_CTX Md5Ctx;
			const char *ts_str;
			const char *rel_uri;
			unsigned char HA1[16];
			unsigned char md5bin[16];

			if (0 != http_auth_digest_hex2bin(mac, maclen, md5bin, sizeof(md5bin))) return 0;

			/* legacy message:
			 *   protected_path := '/' <timestamp-hex> <rel-path>
			 *   timestamp-hex := [0-9a-f]{8}
			 *   rel-path := '/' any*
			 *   (the protected path was already verified)
			 * message = <secret><rel-path><timestamp-hex>
			 */
			ts_str = protected_path + 1;
			rel_uri = ts_str + 8;

			li_MD5_Init(&Md5Ctx);
			li_MD5_Update(&Md5Ctx, CONST_BUF_LEN(config->secret));
			li_MD5_Update(&Md5Ctx, rel_uri, strlen(rel_uri));
			li_MD5_Update(&Md5Ctx, ts_str, 8);
			li_MD5_Final(HA1, &Md5Ctx);

			return const_time_memeq((char *)HA1, (char *)md5bin, sizeof(md5bin));
		}
	case SECDL_HMAC_SHA1:
#ifdef USE_LIB_CRYPTO
		{
			unsigned char digest[20];
			char base64_digest[27];

		  #if defined(USE_NETTLE_CRYPTO)
			struct hmac_sha1_ctx ctx;
			hmac_sha1_set_key(&ctx, buffer_string_length(config->secret), (const uint8_t *)config->secret->ptr);
			hmac_sha1_update(&ctx, strlen(protected_path), (const uint8_t *)protected_path);
			hmac_sha1_digest(&ctx, sizeof(digest), (uint8_t *)digest);
		  #elif defined(USE_OPENSSL_CRYPTO)
			if (NULL == HMAC(
					EVP_sha1(),
					(unsigned char const*) config->secret->ptr, buffer_string_length(config->secret),
					(unsigned char const*) protected_path, strlen(protected_path),
					digest, NULL)) {
				log_error(errh, __FILE__, __LINE__,
				  "hmac-sha1: HMAC() failed");
				return 0;
			}
		  #else
		  #error "unexpected; crypto lib not configured for use by mod_secdownload"
		  #endif

			li_to_base64_no_padding(base64_digest, 27, digest, 20, BASE64_URL);

			return (27 == maclen) && const_time_memeq(mac, base64_digest, 27);
		}
#endif
		break;
	case SECDL_HMAC_SHA256:
#ifdef USE_LIB_CRYPTO
		{
			unsigned char digest[32];
			char base64_digest[43];

		  #if defined(USE_NETTLE_CRYPTO)
			struct hmac_sha256_ctx ctx;
			hmac_sha256_set_key(&ctx, buffer_string_length(config->secret), (const uint8_t *)config->secret->ptr);
			hmac_sha256_update(&ctx, strlen(protected_path), (const uint8_t *)protected_path);
			hmac_sha256_digest(&ctx, sizeof(digest), (uint8_t *)digest);
		  #elif defined(USE_OPENSSL_CRYPTO)
			if (NULL == HMAC(
					EVP_sha256(),
					(unsigned char const*) config->secret->ptr, buffer_string_length(config->secret),
					(unsigned char const*) protected_path, strlen(protected_path),
					digest, NULL)) {
				log_error(errh, __FILE__, __LINE__,
				  "hmac-sha256: HMAC() failed");
				return 0;
			}
		  #else
		  #error "unexpected; crypto lib not configured for use by mod_secdownload"
		  #endif

			li_to_base64_no_padding(base64_digest, 43, digest, 32, BASE64_URL);

			return (43 == maclen) && const_time_memeq(mac, base64_digest, 43);
		}
#endif
		break;
	}

	return 0;
}

INIT_FUNC(mod_secdownload_init) {
    return calloc(1, sizeof(plugin_data));
}

static int mod_secdownload_parse_algorithm(config_plugin_value_t * const cpv, log_error_st * const errh) {
    secdl_algorithm algorithm = algorithm_from_string(cpv->v.b);
    switch (algorithm) {
      case SECDL_INVALID:
        log_error(errh, __FILE__, __LINE__,
          "invalid secdownload.algorithm: %s", cpv->v.b->ptr);
        return 0;
     #ifndef USE_LIB_CRYPTO
      case SECDL_HMAC_SHA1:
      case SECDL_HMAC_SHA256:
        log_error(errh, __FILE__, __LINE__,
          "unsupported secdownload.algorithm: %s", cpv->v.b->ptr);
        /*return 0;*/
        /* proceed to allow config to load for other tests */
        /* (use of unsupported algorithm will result in failure at runtime) */
        break;
     #endif
      default:
        break;
    }

    cpv->vtype = T_CONFIG_INT;
    cpv->v.u = algorithm;
    return 1;
}

static void mod_secdownload_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* secdownload.secret */
        pconf->secret = cpv->v.b;
        break;
      case 1: /* secdownload.document-root */
        pconf->doc_root = cpv->v.b;
        break;
      case 2: /* secdownload.uri-prefix */
        pconf->uri_prefix = cpv->v.b;
        break;
      case 3: /* secdownload.timeout */
        pconf->timeout = cpv->v.u;
        break;
      case 4: /* secdownload.algorithm */
        pconf->algorithm = cpv->v.u; /* mod_secdownload_parse_algorithm() */
        break;
      case 5: /* secdownload.path-segments */
        pconf->path_segments = cpv->v.shrt;
        break;
      case 6: /* secdownload.hash-querystr */
        pconf->hash_querystr = cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_secdownload_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_secdownload_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_secdownload_patch_config(request_st * const r, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_secdownload_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_secdownload_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("secdownload.secret"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("secdownload.document-root"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("secdownload.uri-prefix"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("secdownload.timeout"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("secdownload.algorithm"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("secdownload.path-segments"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("secdownload.hash-querystr"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_secdownload"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* secdownload.secret */
              case 1: /* secdownload.document-root */
              case 2: /* secdownload.uri-prefix */
              case 3: /* secdownload.timeout */
                break;
              case 4: /* secdownload.algorithm */
                if (!mod_secdownload_parse_algorithm(cpv, srv->errh))
                    return HANDLER_ERROR;
                break;
              case 5: /* secdownload.path-segments */
              case 6: /* secdownload.hash-querystr */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.timeout = 60;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_secdownload_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

/**
 * checks if the supplied string is a hex string
 *
 * @param str a possible hex string
 * @return if the supplied string is a valid hex string 1 is returned otherwise 0
 */

static int is_hex_len(const char *str, size_t len) {
	size_t i;

	if (NULL == str) return 0;

	for (i = 0; i < len && *str; i++, str++) {
		/* illegal characters */
		if (!((*str >= '0' && *str <= '9') ||
		      (*str >= 'a' && *str <= 'f') ||
		      (*str >= 'A' && *str <= 'F'))
		    ) {
			return 0;
		}
	}

	return i == len;
}

/**
 * checks if the supplied string is a base64 (modified URL) string
 *
 * @param str a possible base64 (modified URL) string
 * @return if the supplied string is a valid base64 (modified URL) string 1 is returned otherwise 0
 */

static int is_base64_len(const char *str, size_t len) {
	size_t i;

	if (NULL == str) return 0;

	for (i = 0; i < len && *str; i++, str++) {
		/* illegal characters */
		if (!((*str >= '0' && *str <= '9') ||
		      (*str >= 'a' && *str <= 'z') ||
		      (*str >= 'A' && *str <= 'Z') ||
		      (*str == '-') || (*str == '_'))
		    ) {
			return 0;
		}
	}

	return i == len;
}

URIHANDLER_FUNC(mod_secdownload_uri_handler) {
	plugin_data *p = p_d;
	const char *rel_uri, *ts_str, *mac_str, *protected_path;
	time_t ts = 0;
	size_t i, mac_len;

	if (NULL != r->handler_module) return HANDLER_GO_ON;

  #ifdef __COVERITY__
	if (buffer_is_empty(&r->uri.path)) return HANDLER_GO_ON;
  #endif

	mod_secdownload_patch_config(r, p);

	if (buffer_string_is_empty(p->conf.uri_prefix)) return HANDLER_GO_ON;

	if (buffer_string_is_empty(p->conf.secret)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "secdownload.secret has to be set");
		r->http_status = 500;
		return HANDLER_FINISHED;
	}

	if (buffer_string_is_empty(p->conf.doc_root)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "secdownload.document-root has to be set");
		r->http_status = 500;
		return HANDLER_FINISHED;
	}

	if (SECDL_INVALID == p->conf.algorithm) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "secdownload.algorithm has to be set");
		r->http_status = 500;
		return HANDLER_FINISHED;
	}

	mac_len = secdl_algorithm_mac_length(p->conf.algorithm);

	if (0 != strncmp(r->uri.path.ptr, p->conf.uri_prefix->ptr, buffer_string_length(p->conf.uri_prefix))) return HANDLER_GO_ON;

	mac_str = r->uri.path.ptr + buffer_string_length(p->conf.uri_prefix);

	if (!is_base64_len(mac_str, mac_len)) return HANDLER_GO_ON;

	protected_path = mac_str + mac_len;
	if (*protected_path != '/') return HANDLER_GO_ON;

	ts_str = protected_path + 1;
	if (!is_hex_len(ts_str, 8)) return HANDLER_GO_ON;
	if (*(ts_str + 8) != '/') return HANDLER_GO_ON;

	for (i = 0; i < 8; i++) {
		ts = (ts << 4) + hex2int(ts_str[i]);
	}

	const time_t cur_ts = log_epoch_secs;

	/* timed-out */
	if ( (cur_ts > ts && (unsigned int) (cur_ts - ts) > p->conf.timeout) ||
	     (cur_ts < ts && (unsigned int) (ts - cur_ts) > p->conf.timeout) ) {
		/* "Gone" as the url will never be valid again instead of "408 - Timeout" where the request may be repeated */
		r->http_status = 410;

		return HANDLER_FINISHED;
	}

	rel_uri = ts_str + 8;

	buffer * const tb = r->tmp_buf;

	if (p->conf.path_segments) {
		const char *rel_uri_end = rel_uri;
		unsigned int count = p->conf.path_segments;
		do {
			rel_uri_end = strchr(rel_uri_end+1, '/');
		} while (rel_uri_end && --count);
		if (rel_uri_end) {
			buffer_copy_string_len(tb, protected_path,
					       rel_uri_end - protected_path);
			protected_path = tb->ptr;
		}
	}

	if (p->conf.hash_querystr && !buffer_is_empty(&r->uri.query)) {
		if (protected_path != tb->ptr) {
			buffer_copy_string(tb, protected_path);
		}
		buffer_append_string_len(tb, CONST_STR_LEN("?"));
		buffer_append_string_buffer(tb, &r->uri.query);
		/* assign last in case tb->ptr is reallocated */
		protected_path = tb->ptr;
	}

	if (!secdl_verify_mac(&p->conf, protected_path, mac_str, mac_len,
	                      r->conf.errh)) {
		r->http_status = 403;

		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "mac invalid: %s", r->uri.path.ptr);
		}

		return HANDLER_FINISHED;
	}

	/* starting with the last / we should have relative-path to the docroot
	 */

	buffer_copy_buffer(&r->physical.doc_root, p->conf.doc_root);
	buffer_copy_buffer(&r->physical.basedir, p->conf.doc_root);
	buffer_copy_string(&r->physical.rel_path, rel_uri);
	buffer_copy_buffer(&r->physical.path, &r->physical.doc_root);
	buffer_append_string_buffer(&r->physical.path, &r->physical.rel_path);

	return HANDLER_GO_ON;
}


int mod_secdownload_plugin_init(plugin *p);
int mod_secdownload_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "secdownload";

	p->init        = mod_secdownload_init;
	p->handle_physical  = mod_secdownload_uri_handler;
	p->set_defaults  = mod_secdownload_set_defaults;

	return 0;
}
