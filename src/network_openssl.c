#include "first.h"

#include "network_backends.h"

#if defined(USE_OPENSSL)

#include "network.h"
#include "log.h"
#include "configfile.h"
#include "plugin.h"

#include <unistd.h>
#include <stdlib.h>

#include <errno.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#include <openssl/bn.h>

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
# ifndef OPENSSL_NO_ECDH
#  include <openssl/ecdh.h>
# endif
#endif

static int load_next_chunk(server *srv, connection *con, chunkqueue *cq, off_t max_bytes, const char **data, size_t *data_len) {
	chunk * const c = cq->first;

#define LOCAL_SEND_BUFSIZE (64 * 1024)
	/* this is a 64k sendbuffer
	 *
	 * it has to stay at the same location all the time to satisfy the needs
	 * of SSL_write to pass the SAME parameter in case of a _WANT_WRITE
	 *
	 * the buffer is allocated once, is NOT realloced and is NOT freed at shutdown
	 * -> we expect a 64k block to 'leak' in valgrind
	 * */
	static char *local_send_buffer = NULL;

	force_assert(NULL != c);

	switch (c->type) {
	case MEM_CHUNK:
		{
			size_t have;

			force_assert(c->offset >= 0 && c->offset <= (off_t)buffer_string_length(c->mem));

			have = buffer_string_length(c->mem) - c->offset;
			if ((off_t) have > max_bytes) have = max_bytes;

			*data = c->mem->ptr + c->offset;
			*data_len = have;
		}
		return 0;

	case FILE_CHUNK:
		if (NULL == local_send_buffer) {
			local_send_buffer = malloc(LOCAL_SEND_BUFSIZE);
			force_assert(NULL != local_send_buffer);
		}

		if (0 != network_open_file_chunk(srv, con, cq)) return -1;

		{
			off_t offset, toSend;

			force_assert(c->offset >= 0 && c->offset <= c->file.length);
			offset = c->file.start + c->offset;
			toSend = c->file.length - c->offset;

			if (toSend > LOCAL_SEND_BUFSIZE) toSend = LOCAL_SEND_BUFSIZE;
			if (toSend > max_bytes) toSend = max_bytes;

			if (-1 == lseek(c->file.fd, offset, SEEK_SET)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "lseek: ", strerror(errno));
				return -1;
			}
			if (-1 == (toSend = read(c->file.fd, local_send_buffer, toSend))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "read: ", strerror(errno));
				return -1;
			}

			*data = local_send_buffer;
			*data_len = toSend;
		}
		return 0;
	}

	return -1;
}

static void ssl_info_callback(const SSL *ssl, int where, int ret) {
	UNUSED(ret);

	if (0 != (where & SSL_CB_HANDSHAKE_START)) {
		connection *con = SSL_get_app_data(ssl);
		++con->renegotiations;
	}
}

static X509* x509_load_pem_file(server *srv, const char *file) {
	BIO *in;
	X509 *x = NULL;

	in = BIO_new(BIO_s_file());
	if (NULL == in) {
		log_error_write(srv, __FILE__, __LINE__, "S", "SSL: BIO_new(BIO_s_file()) failed");
		goto error;
	}

	if (BIO_read_filename(in,file) <= 0) {
		log_error_write(srv, __FILE__, __LINE__, "SSS", "SSL: BIO_read_filename('", file,"') failed");
		goto error;
	}
	x = PEM_read_bio_X509(in, NULL, NULL, NULL);

	if (NULL == x) {
		log_error_write(srv, __FILE__, __LINE__, "SSS", "SSL: couldn't read X509 certificate from '", file,"'");
		goto error;
	}

	BIO_free(in);
	return x;

error:
	if (NULL != in) BIO_free(in);
	return NULL;
}

static EVP_PKEY* evp_pkey_load_pem_file(server *srv, const char *file) {
	BIO *in;
	EVP_PKEY *x = NULL;

	in=BIO_new(BIO_s_file());
	if (NULL == in) {
		log_error_write(srv, __FILE__, __LINE__, "s", "SSL: BIO_new(BIO_s_file()) failed");
		goto error;
	}

	if (BIO_read_filename(in,file) <= 0) {
		log_error_write(srv, __FILE__, __LINE__, "SSS", "SSL: BIO_read_filename('", file,"') failed");
		goto error;
	}
	x = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);

	if (NULL == x) {
		log_error_write(srv, __FILE__, __LINE__, "SSS", "SSL: couldn't read private key from '", file,"'");
		goto error;
	}

	BIO_free(in);
	return x;

error:
	if (NULL != in) BIO_free(in);
	return NULL;
}

static int network_openssl_load_pemfile(server *srv, size_t ndx) {
	specific_config *s = srv->config_storage[ndx];

#ifdef OPENSSL_NO_TLSEXT
	{
		data_config *dc = (data_config *)srv->config_context->data[ndx];
		if ((ndx > 0 && (COMP_SERVER_SOCKET != dc->comp || dc->cond != CONFIG_COND_EQ))
			|| !s->ssl_enabled) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
					"ssl.pemfile only works in SSL socket binding context as openssl version does not support TLS extensions");
			return -1;
		}
	}
#endif

	if (NULL == (s->ssl_pemfile_x509 = x509_load_pem_file(srv, s->ssl_pemfile->ptr))) return -1;
	if (NULL == (s->ssl_pemfile_pkey = evp_pkey_load_pem_file(srv, s->ssl_pemfile->ptr))) return -1;

	if (!X509_check_private_key(s->ssl_pemfile_x509, s->ssl_pemfile_pkey)) {
		log_error_write(srv, __FILE__, __LINE__, "sssb", "SSL:",
				"Private key does not match the certificate public key, reason:",
				ERR_error_string(ERR_get_error(), NULL),
				s->ssl_pemfile);
		return -1;
	}

	return 0;
}

#define PATCH(x) con->conf.x = s->x
static int openssl_setup_connection(server *srv, connection *con) {
	specific_config *s = srv->config_storage[0];

	PATCH(ssl_pemfile_x509);
	PATCH(ssl_pemfile_pkey);
	PATCH(ssl_ca_file_cert_names);

	return 0;
}

static int openssl_patch_connection(server *srv, connection *con) {
	size_t i, j;

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		specific_config *s = srv->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.pemfile"))) {
				PATCH(ssl_pemfile_x509);
				PATCH(ssl_pemfile_pkey);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.ca-file"))) {
				PATCH(ssl_ca_file_cert_names);
			}
		}
	}

	return 0;
}
#undef PATCH

#ifndef OPENSSL_NO_TLSEXT
static int network_ssl_servername_callback(SSL *ssl, int *al, server *srv) {
	const char *servername;
	connection *con = (connection *) SSL_get_app_data(ssl);
	UNUSED(al);

	buffer_copy_string(con->uri.scheme, "https");

	if (NULL == (servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))) {
#if 0
		/* this "error" just means the client didn't support it */
		log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
				"failed to get TLS server name");
#endif
		return SSL_TLSEXT_ERR_NOACK;
	}
	buffer_copy_string(con->tlsext_server_name, servername);
	buffer_to_lower(con->tlsext_server_name);

	/* Sometimes this is still set, confusing COMP_HTTP_HOST */
	buffer_reset(con->uri.authority);

	config_cond_cache_reset(srv, con);
	config_setup_connection(srv, con);
	openssl_setup_connection(srv, con);

	con->conditional_is_valid[COMP_SERVER_SOCKET] = 1;
	con->conditional_is_valid[COMP_HTTP_REMOTE_IP] = 1;
	con->conditional_is_valid[COMP_HTTP_SCHEME] = 1;
	con->conditional_is_valid[COMP_HTTP_HOST] = 1;
	config_patch_connection(srv, con);
	openssl_patch_connection(srv, con);

	if (NULL == con->conf.ssl_pemfile_x509 || NULL == con->conf.ssl_pemfile_pkey) {
		/* x509/pkey available <=> pemfile was set <=> pemfile got patched: so this should never happen, unless you nest $SERVER["socket"] */
		log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
			"no certificate/private key for TLS server name", con->tlsext_server_name);
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	/* first set certificate! setting private key checks whether certificate matches it */
	if (!SSL_use_certificate(ssl, con->conf.ssl_pemfile_x509)) {
		log_error_write(srv, __FILE__, __LINE__, "ssb:s", "SSL:",
			"failed to set certificate for TLS server name", con->tlsext_server_name,
			ERR_error_string(ERR_get_error(), NULL));
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	if (!SSL_use_PrivateKey(ssl, con->conf.ssl_pemfile_pkey)) {
		log_error_write(srv, __FILE__, __LINE__, "ssb:s", "SSL:",
			"failed to set private key for TLS server name", con->tlsext_server_name,
			ERR_error_string(ERR_get_error(), NULL));
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	if (con->conf.ssl_verifyclient) {
		if (NULL == con->conf.ssl_ca_file_cert_names) {
			log_error_write(srv, __FILE__, __LINE__, "ssb:s", "SSL:",
				"can't verify client without ssl.ca-file for TLS server name", con->tlsext_server_name,
				ERR_error_string(ERR_get_error(), NULL));
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		}

		SSL_set_client_CA_list(ssl, SSL_dup_CA_list(con->conf.ssl_ca_file_cert_names));
		/* forcing verification here is really not that useful - a client could just connect without SNI */
		SSL_set_verify(
			ssl,
			SSL_VERIFY_PEER | (con->conf.ssl_verifyclient_enforce ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
			NULL
		);
		SSL_set_verify_depth(ssl, con->conf.ssl_verifyclient_depth);
	} else {
		SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
	}

	return SSL_TLSEXT_ERR_OK;
}
#endif

int network_init_openssl(server *srv)
{
	size_t i, j;
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	EC_KEY *ecdh;
	int nid;
#endif
#endif

# ifndef OPENSSL_NO_DH
	DH *dh;
# endif
	BIO *bio;

       /* 1024-bit MODP Group with 160-bit prime order subgroup (RFC5114)
	* -----BEGIN DH PARAMETERS-----
	* MIIBDAKBgQCxC4+WoIDgHd6S3l6uXVTsUsmfvPsGo8aaap3KUtI7YWBz4oZ1oj0Y
	* mDjvHi7mUsAT7LSuqQYRIySXXDzUm4O/rMvdfZDEvXCYSI6cIZpzck7/1vrlZEc4
	* +qMaT/VbzMChUa9fDci0vUW/N982XBpl5oz9p21NpwjfH7K8LkpDcQKBgQCk0cvV
	* w/00EmdlpELvuZkF+BBN0lisUH/WQGz/FCZtMSZv6h5cQVZLd35pD1UE8hMWAhe0
	* sBuIal6RVH+eJ0n01/vX07mpLuGQnQ0iY/gKdqaiTAh6CR9THb8KAWm2oorWYqTR
	* jnOvoy13nVkY0IvIhY9Nzvl8KiSFXm7rIrOy5QICAKA=
	* -----END DH PARAMETERS-----
	*/

	static const unsigned char dh1024_p[]={
		0xB1,0x0B,0x8F,0x96,0xA0,0x80,0xE0,0x1D,0xDE,0x92,0xDE,0x5E,
		0xAE,0x5D,0x54,0xEC,0x52,0xC9,0x9F,0xBC,0xFB,0x06,0xA3,0xC6,
		0x9A,0x6A,0x9D,0xCA,0x52,0xD2,0x3B,0x61,0x60,0x73,0xE2,0x86,
		0x75,0xA2,0x3D,0x18,0x98,0x38,0xEF,0x1E,0x2E,0xE6,0x52,0xC0,
		0x13,0xEC,0xB4,0xAE,0xA9,0x06,0x11,0x23,0x24,0x97,0x5C,0x3C,
		0xD4,0x9B,0x83,0xBF,0xAC,0xCB,0xDD,0x7D,0x90,0xC4,0xBD,0x70,
		0x98,0x48,0x8E,0x9C,0x21,0x9A,0x73,0x72,0x4E,0xFF,0xD6,0xFA,
		0xE5,0x64,0x47,0x38,0xFA,0xA3,0x1A,0x4F,0xF5,0x5B,0xCC,0xC0,
		0xA1,0x51,0xAF,0x5F,0x0D,0xC8,0xB4,0xBD,0x45,0xBF,0x37,0xDF,
		0x36,0x5C,0x1A,0x65,0xE6,0x8C,0xFD,0xA7,0x6D,0x4D,0xA7,0x08,
		0xDF,0x1F,0xB2,0xBC,0x2E,0x4A,0x43,0x71,
	};

	static const unsigned char dh1024_g[]={
		0xA4,0xD1,0xCB,0xD5,0xC3,0xFD,0x34,0x12,0x67,0x65,0xA4,0x42,
		0xEF,0xB9,0x99,0x05,0xF8,0x10,0x4D,0xD2,0x58,0xAC,0x50,0x7F,
		0xD6,0x40,0x6C,0xFF,0x14,0x26,0x6D,0x31,0x26,0x6F,0xEA,0x1E,
		0x5C,0x41,0x56,0x4B,0x77,0x7E,0x69,0x0F,0x55,0x04,0xF2,0x13,
		0x16,0x02,0x17,0xB4,0xB0,0x1B,0x88,0x6A,0x5E,0x91,0x54,0x7F,
		0x9E,0x27,0x49,0xF4,0xD7,0xFB,0xD7,0xD3,0xB9,0xA9,0x2E,0xE1,
		0x90,0x9D,0x0D,0x22,0x63,0xF8,0x0A,0x76,0xA6,0xA2,0x4C,0x08,
		0x7A,0x09,0x1F,0x53,0x1D,0xBF,0x0A,0x01,0x69,0xB6,0xA2,0x8A,
		0xD6,0x62,0xA4,0xD1,0x8E,0x73,0xAF,0xA3,0x2D,0x77,0x9D,0x59,
		0x18,0xD0,0x8B,0xC8,0x85,0x8F,0x4D,0xCE,0xF9,0x7C,0x2A,0x24,
		0x85,0x5E,0x6E,0xEB,0x22,0xB3,0xB2,0xE5,
	};

	/* load SSL certificates */
	for (i = 0; i < srv->config_context->used; i++) {
		specific_config *s = srv->config_storage[i];
#ifndef SSL_OP_NO_COMPRESSION
# define SSL_OP_NO_COMPRESSION 0
#endif
#ifndef SSL_MODE_RELEASE_BUFFERS    /* OpenSSL >= 1.0.0 */
#define SSL_MODE_RELEASE_BUFFERS 0
#endif
		long ssloptions =
			SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_NO_COMPRESSION;

		if (buffer_string_is_empty(s->ssl_pemfile) && buffer_string_is_empty(s->ssl_ca_file)) continue;

		if (srv->ssl_is_init == 0) {
		      #if OPENSSL_VERSION_NUMBER >= 0x10100000L \
		       && !defined(LIBRESSL_VERSION_NUMBER)
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
					|OPENSSL_INIT_LOAD_CRYPTO_STRINGS,NULL);
			OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
					   |OPENSSL_INIT_ADD_ALL_DIGESTS
					   |OPENSSL_INIT_LOAD_CONFIG, NULL);
		      #else
			SSL_load_error_strings();
			SSL_library_init();
			OpenSSL_add_all_algorithms();
		      #endif
			srv->ssl_is_init = 1;

			if (0 == RAND_status()) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						"not enough entropy in the pool");
				return -1;
			}
		}

		if (!buffer_string_is_empty(s->ssl_pemfile)) {
#ifdef OPENSSL_NO_TLSEXT
			data_config *dc = (data_config *)srv->config_context->data[i];
			if (COMP_HTTP_HOST == dc->comp) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						"can't use ssl.pemfile with $HTTP[\"host\"], openssl version does not support TLS extensions");
				return -1;
			}
#endif
			if (network_openssl_load_pemfile(srv, i)) return -1;
		}


		if (!buffer_string_is_empty(s->ssl_ca_file)) {
			s->ssl_ca_file_cert_names = SSL_load_client_CA_file(s->ssl_ca_file->ptr);
			if (NULL == s->ssl_ca_file_cert_names) {
				log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
						ERR_error_string(ERR_get_error(), NULL), s->ssl_ca_file);
			}
		}

		if (buffer_string_is_empty(s->ssl_pemfile) || !s->ssl_enabled) continue;

		if (NULL == (s->ssl_ctx = SSL_CTX_new(SSLv23_server_method()))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
					ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}

		/* completely useless identifier; required for client cert verification to work with sessions */
		if (0 == SSL_CTX_set_session_id_context(s->ssl_ctx, (const unsigned char*) CONST_STR_LEN("lighttpd"))) {
			log_error_write(srv, __FILE__, __LINE__, "ss:s", "SSL:",
				"failed to set session context",
				ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}

		if (s->ssl_empty_fragments) {
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
			ssloptions &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
#else
			ssloptions &= ~0x00000800L; /* hardcode constant */
			log_error_write(srv, __FILE__, __LINE__, "ss", "WARNING: SSL:",
					"'insert empty fragments' not supported by the openssl version used to compile lighttpd with");
#endif
		}

		SSL_CTX_set_options(s->ssl_ctx, ssloptions);
		SSL_CTX_set_info_callback(s->ssl_ctx, ssl_info_callback);

		if (!s->ssl_use_sslv2 && 0 != SSL_OP_NO_SSLv2) {
			/* disable SSLv2 */
			if ((SSL_OP_NO_SSLv2 & SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv2)) != SSL_OP_NO_SSLv2) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}
		}

		if (!s->ssl_use_sslv3 && 0 != SSL_OP_NO_SSLv3) {
			/* disable SSLv3 */
			if ((SSL_OP_NO_SSLv3 & SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv3)) != SSL_OP_NO_SSLv3) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}
		}

		if (!buffer_string_is_empty(s->ssl_cipher_list)) {
			/* Disable support for low encryption ciphers */
			if (SSL_CTX_set_cipher_list(s->ssl_ctx, s->ssl_cipher_list->ptr) != 1) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}

			if (s->ssl_honor_cipher_order) {
				SSL_CTX_set_options(s->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
			}
		}

#ifndef OPENSSL_NO_DH
		/* Support for Diffie-Hellman key exchange */
		if (!buffer_string_is_empty(s->ssl_dh_file)) {
			/* DH parameters from file */
			bio = BIO_new_file((char *) s->ssl_dh_file->ptr, "r");
			if (bio == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL: Unable to open file", s->ssl_dh_file->ptr);
				return -1;
			}
			dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
			BIO_free(bio);
			if (dh == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL: PEM_read_bio_DHparams failed", s->ssl_dh_file->ptr);
				return -1;
			}
		} else {
			BIGNUM *dh_p, *dh_g;
			/* Default DH parameters from RFC5114 */
			dh = DH_new();
			if (dh == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "s", "SSL: DH_new () failed");
				return -1;
			}
			dh_p = BN_bin2bn(dh1024_p,sizeof(dh1024_p), NULL);
			dh_g = BN_bin2bn(dh1024_g,sizeof(dh1024_g), NULL);
			if ((dh_p == NULL) || (dh_g == NULL)) {
				DH_free(dh);
				log_error_write(srv, __FILE__, __LINE__, "s", "SSL: BN_bin2bn () failed");
				return -1;
			}
		      #if OPENSSL_VERSION_NUMBER < 0x10100000L \
			|| defined(LIBRESSL_VERSION_NUMBER)
			dh->p = dh_p;
			dh->g = dh_g;
			dh->length = 160;
		      #else
			DH_set0_pqg(dh, dh_p, NULL, dh_g);
			DH_set_length(dh, 160);
		      #endif
		}
		SSL_CTX_set_tmp_dh(s->ssl_ctx,dh);
		SSL_CTX_set_options(s->ssl_ctx,SSL_OP_SINGLE_DH_USE);
		DH_free(dh);
#else
		if (!buffer_string_is_empty(s->ssl_dh_file)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SSL: openssl compiled without DH support, can't load parameters from", s->ssl_dh_file->ptr);
		}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
		/* Support for Elliptic-Curve Diffie-Hellman key exchange */
		if (!buffer_string_is_empty(s->ssl_ec_curve)) {
			/* OpenSSL only supports the "named curves" from RFC 4492, section 5.1.1. */
			nid = OBJ_sn2nid((char *) s->ssl_ec_curve->ptr);
			if (nid == 0) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL: Unknown curve name", s->ssl_ec_curve->ptr);
				return -1;
			}
		} else {
			/* Default curve */
			nid = OBJ_sn2nid("prime256v1");
		}
		ecdh = EC_KEY_new_by_curve_name(nid);
		if (ecdh == NULL) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SSL: Unable to create curve", s->ssl_ec_curve->ptr);
			return -1;
		}
		SSL_CTX_set_tmp_ecdh(s->ssl_ctx,ecdh);
		SSL_CTX_set_options(s->ssl_ctx,SSL_OP_SINGLE_ECDH_USE);
		EC_KEY_free(ecdh);
#endif
#endif

		/* load all ssl.ca-files specified in the config into each SSL_CTX to be prepared for SNI */
		for (j = 0; j < srv->config_context->used; j++) {
			specific_config *s1 = srv->config_storage[j];

			if (!buffer_string_is_empty(s1->ssl_ca_file)) {
				if (1 != SSL_CTX_load_verify_locations(s->ssl_ctx, s1->ssl_ca_file->ptr, NULL)) {
					log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
							ERR_error_string(ERR_get_error(), NULL), s1->ssl_ca_file);
					return -1;
				}
			}
		}

		if (s->ssl_verifyclient) {
			if (NULL == s->ssl_ca_file_cert_names) {
				log_error_write(srv, __FILE__, __LINE__, "s",
					"SSL: You specified ssl.verifyclient.activate but no ca_file"
				);
				return -1;
			}
			SSL_CTX_set_client_CA_list(s->ssl_ctx, SSL_dup_CA_list(s->ssl_ca_file_cert_names));
			SSL_CTX_set_verify(
				s->ssl_ctx,
				SSL_VERIFY_PEER | (s->ssl_verifyclient_enforce ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
				NULL
			);
			SSL_CTX_set_verify_depth(s->ssl_ctx, s->ssl_verifyclient_depth);
		}

		if (1 != SSL_CTX_use_certificate(s->ssl_ctx, s->ssl_pemfile_x509)) {
			log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
					ERR_error_string(ERR_get_error(), NULL), s->ssl_pemfile);
			return -1;
		}

		if (1 != SSL_CTX_use_PrivateKey(s->ssl_ctx, s->ssl_pemfile_pkey)) {
			log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
					ERR_error_string(ERR_get_error(), NULL), s->ssl_pemfile);
			return -1;
		}

		if (SSL_CTX_check_private_key(s->ssl_ctx) != 1) {
			log_error_write(srv, __FILE__, __LINE__, "sssb", "SSL:",
					"Private key does not match the certificate public key, reason:",
					ERR_error_string(ERR_get_error(), NULL),
					s->ssl_pemfile);
			return -1;
		}
		SSL_CTX_set_default_read_ahead(s->ssl_ctx, 1);
		SSL_CTX_set_mode(s->ssl_ctx,  SSL_CTX_get_mode(s->ssl_ctx)
					    | SSL_MODE_ENABLE_PARTIAL_WRITE
					    | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
					    | SSL_MODE_RELEASE_BUFFERS);

# ifndef OPENSSL_NO_TLSEXT
		if (!SSL_CTX_set_tlsext_servername_callback(s->ssl_ctx, network_ssl_servername_callback) ||
		    !SSL_CTX_set_tlsext_servername_arg(s->ssl_ctx, srv)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
					"failed to initialize TLS servername callback, openssl library does not support TLS servername extension");
			return -1;
		}
# endif
	}

	srv->network_ssl_backend_write = network_write_chunkqueue_openssl;

	return 0;
}

void network_free_openssl(server *srv)
{
	size_t i;
	if (srv->config_storage) {
		for (i = 0; i < srv->config_context->used; i++) {
			specific_config *s = srv->config_storage[i];

			if (!s) continue;

			SSL_CTX_free(s->ssl_ctx);
			EVP_PKEY_free(s->ssl_pemfile_pkey);
			X509_free(s->ssl_pemfile_x509);
			if (NULL != s->ssl_ca_file_cert_names) sk_X509_NAME_pop_free(s->ssl_ca_file_cert_names, X509_NAME_free);
		}
	}
	if (srv->ssl_is_init) {
	      #if   OPENSSL_VERSION_NUMBER >= 0x10100000L \
		&& !defined(LIBRESSL_VERSION_NUMBER)
		/*(OpenSSL libraries handle thread init and deinit)
		 * https://github.com/openssl/openssl/pull/1048 */
	      #else
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();
	       #if OPENSSL_VERSION_NUMBER >= 0x10000000L
		ERR_remove_thread_state(NULL);
	       #else
		ERR_remove_state(0);
	       #endif
		EVP_cleanup();
	      #endif
	}
}

int network_write_chunkqueue_openssl(server *srv, connection *con, SSL *ssl, chunkqueue *cq, off_t max_bytes) {
	/* the remote side closed the connection before without shutdown request
	 * - IE
	 * - wget
	 * if keep-alive is disabled */

	if (con->keep_alive == 0) {
		SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
	}

	chunkqueue_remove_finished_chunks(cq);

	while (max_bytes > 0 && NULL != cq->first) {
		const char *data;
		size_t data_len;
		int r;

		if (0 != load_next_chunk(srv, con, cq, max_bytes, &data, &data_len)) return -1;

		/**
		 * SSL_write man-page
		 *
		 * WARNING
		 *        When an SSL_write() operation has to be repeated because of
		 *        SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be
		 *        repeated with the same arguments.
		 */

		ERR_clear_error();
		r = SSL_write(ssl, data, data_len);

		if (con->renegotiations > 1 && con->conf.ssl_disable_client_renegotiation) {
			log_error_write(srv, __FILE__, __LINE__, "s", "SSL: renegotiation initiated by client, killing connection");
			return -1;
		}

		if (r <= 0) {
			int ssl_r;
			unsigned long err;

			switch ((ssl_r = SSL_get_error(ssl, r))) {
			case SSL_ERROR_WANT_READ:
				con->is_readable = -1;
				return 0; /* try again later */
			case SSL_ERROR_WANT_WRITE:
				con->is_writable = -1;
				return 0; /* try again later */
			case SSL_ERROR_SYSCALL:
				/* perhaps we have error waiting in our error-queue */
				if (0 != (err = ERR_get_error())) {
					do {
						log_error_write(srv, __FILE__, __LINE__, "sdds", "SSL:",
								ssl_r, r,
								ERR_error_string(err, NULL));
					} while((err = ERR_get_error()));
				} else if (r == -1) {
					/* no, but we have errno */
					switch(errno) {
					case EPIPE:
					case ECONNRESET:
						return -2;
					default:
						log_error_write(srv, __FILE__, __LINE__, "sddds", "SSL:",
								ssl_r, r, errno,
								strerror(errno));
						break;
					}
				} else {
					/* neither error-queue nor errno ? */
					log_error_write(srv, __FILE__, __LINE__, "sddds", "SSL (error):",
							ssl_r, r, errno,
							strerror(errno));
				}
				break;

			case SSL_ERROR_ZERO_RETURN:
				/* clean shutdown on the remote side */

				if (r == 0) return -2;

				/* fall through */
			default:
				while((err = ERR_get_error())) {
					log_error_write(srv, __FILE__, __LINE__, "sdds", "SSL:",
							ssl_r, r,
							ERR_error_string(err, NULL));
				}
				break;
			}
			return -1;
		}

		chunkqueue_mark_written(cq, r);
		max_bytes -= r;

		if ((size_t) r < data_len) break; /* try again later */
	}

	return 0;
}

void https_cgi_env_openssl(server *srv, connection *con) {
    const char *s;
    const SSL_CIPHER *cipher;
    UNUSED(srv);

    if (!con->ssl) return;

    s = SSL_get_version(con->ssl);
    array_set_key_value(con->environment,
                        CONST_STR_LEN("SSL_PROTOCOL"),
                        s, strlen(s));

    if ((cipher = SSL_get_current_cipher(con->ssl))) {
        int usekeysize, algkeysize;
        char buf[LI_ITOSTRING_LENGTH];
        s = SSL_CIPHER_get_name(cipher);
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CIPHER"),
                            s, strlen(s));
        usekeysize = SSL_CIPHER_get_bits(cipher, &algkeysize);
        li_itostrn(buf, sizeof(buf), usekeysize);
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                            buf, strlen(buf));
        li_itostrn(buf, sizeof(buf), algkeysize);
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CIPHER_ALGKEYSIZE"),
                            buf, strlen(buf));
    }
}

void https_response_prepare_openssl(server *srv, connection *con) {
	X509 *xs;
	X509_NAME *xn;
	int i, nentries;

	openssl_patch_connection(srv, con);

	long vr = SSL_get_verify_result(con->ssl);
	if (vr != X509_V_OK) {
		char errstr[256];
		ERR_error_string_n(vr, errstr, sizeof(errstr));
		buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("FAILED:"));
		buffer_append_string(srv->tmp_buf, errstr);
		array_set_key_value(con->environment,
				    CONST_STR_LEN("SSL_CLIENT_VERIFY"),
				    CONST_BUF_LEN(srv->tmp_buf));
		return;
	} else if (!(xs = SSL_get_peer_certificate(con->ssl))) {
		array_set_key_value(con->environment,
				    CONST_STR_LEN("SSL_CLIENT_VERIFY"),
				    CONST_STR_LEN("NONE"));
		return;
	} else {
		array_set_key_value(con->environment,
				    CONST_STR_LEN("SSL_CLIENT_VERIFY"),
				    CONST_STR_LEN("SUCCESS"));
	}

	buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("SSL_CLIENT_S_DN_"));
	xn = X509_get_subject_name(xs);
	for (i = 0, nentries = X509_NAME_entry_count(xn); i < nentries; ++i) {
		int xobjnid;
		const char * xobjsn;
		X509_NAME_ENTRY *xe;

		if (!(xe = X509_NAME_get_entry(xn, i))) {
			continue;
		}
		xobjnid = OBJ_obj2nid((ASN1_OBJECT*)X509_NAME_ENTRY_get_object(xe));
		xobjsn = OBJ_nid2sn(xobjnid);
		if (xobjsn) {
			buffer_string_set_length(srv->tmp_buf, sizeof("SSL_CLIENT_S_DN_")-1);
			buffer_append_string(srv->tmp_buf, xobjsn);
			array_set_key_value(con->environment,
					    CONST_BUF_LEN(srv->tmp_buf),
					    (const char *)X509_NAME_ENTRY_get_data(xe)->data,
					    X509_NAME_ENTRY_get_data(xe)->length);
		}
	}

	{
		ASN1_INTEGER *xsn = X509_get_serialNumber(xs);
		BIGNUM *serialBN = ASN1_INTEGER_to_BN(xsn, NULL);
		char *serialHex = BN_bn2hex(serialBN);
		array_set_key_value(con->environment,
				    CONST_STR_LEN("SSL_CLIENT_M_SERIAL"),
				    serialHex, strlen(serialHex));
		OPENSSL_free(serialHex);
		BN_free(serialBN);
	}

	if (!buffer_string_is_empty(con->conf.ssl_verifyclient_username)) {
		/* pick one of the exported values as "REMOTE_USER", for example
		 * ssl.verifyclient.username   = "SSL_CLIENT_S_DN_UID" or "SSL_CLIENT_S_DN_emailAddress"
		 */
		data_string *ds = (data_string *)array_get_element(con->environment, con->conf.ssl_verifyclient_username->ptr);
		if (ds) array_set_key_value(con->environment, CONST_STR_LEN("REMOTE_USER"), CONST_BUF_LEN(ds->value));
	}

	if (con->conf.ssl_verifyclient_export_cert) {
		BIO *bio;
		if (NULL != (bio = BIO_new(BIO_s_mem()))) {
			data_string *envds;
			int n;

			PEM_write_bio_X509(bio, xs);
			n = BIO_pending(bio);

			if (NULL == (envds = (data_string *)array_get_unused_element(con->environment, TYPE_STRING))) {
				envds = data_string_init();
			}

			buffer_copy_string_len(envds->key, CONST_STR_LEN("SSL_CLIENT_CERT"));
			buffer_string_prepare_copy(envds->value, n);
			BIO_read(bio, envds->value->ptr, n);
			BIO_free(bio);
			buffer_commit(envds->value, n);
			array_replace(con->environment, (data_unset *)envds);
		}
	}
	X509_free(xs);
}
#endif /* USE_OPENSSL */
