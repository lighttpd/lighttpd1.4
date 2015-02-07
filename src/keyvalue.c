#include "server.h"
#include "keyvalue.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static keyvalue http_versions[] = {
	"HTTP/1.1" ,
	"HTTP/1.0" ,
	NULL
};

static keyvalue http_methods[] = {
	"GET" ,
	"HEAD" ,
	"POST" ,
	"PUT" ,
	"DELETE" ,
	"CONNECT" ,
	"OPTIONS" ,
	"TRACE" ,
	"ACL" ,
	"BASELINE-CONTROL" ,
	"BIND" ,
	"CHECKIN" ,
	"CHECKOUT" ,
	"COPY" ,
	"LABEL" ,
	"LINK" ,
	"LOCK",
	"MERGE" ,
	"MKACTIVITY" ,
	"MKCALENDAR" ,
	"MKCOL" ,
	"MKREDIRECTREF" ,
	"MKWORKSPACE" ,
	"MOVE" ,
	"ORDERPATCH" ,
	"PATCH" ,
	"PROPFIND" ,
	"PROPPATCH" ,
	"REBIND" ,
	"REPORT" ,
	"SEARCH" ,
	"UNBIND" ,
	"UNCHECKOUT" ,
	"UNLINK" ,
	"UNLOCK" ,
	"UPDATE" ,
	"UPDATEREDIRECTREF" ,
	"VERSION-CONTROL" ,

	NULL
};

void set_http_status(keyvalue *kv, int key, const char *value)
{
	kv[key-HTTP_STATUS] = value;
}

static keyvalue http_status[412];
/*Remove the http_status init, We have used the macro INIT_HTTP_STATUS instead.*/
#if 0
static keyvalue http_status[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 102, "Processing" }, /* WebDAV */
	{ 200, "OK" },
	{ 201, "Created" },
	{ 202, "Accepted" },
	{ 203, "Non-Authoritative Information" },
	{ 204, "No Content" },
	{ 205, "Reset Content" },
	{ 206, "Partial Content" },
	{ 207, "Multi-status" }, /* WebDAV */
	{ 300, "Multiple Choices" },
	{ 301, "Moved Permanently" },
	{ 302, "Found" },
	{ 303, "See Other" },
	{ 304, "Not Modified" },
	{ 305, "Use Proxy" },
	{ 306, "(Unused)" },
	{ 307, "Temporary Redirect" },
	{ 400, "Bad Request" },
	{ 401, "Unauthorized" },
	{ 402, "Payment Required" },
	{ 403, "Forbidden" },
	{ 404, "Not Found" },
	{ 405, "Method Not Allowed" },
	{ 406, "Not Acceptable" },
	{ 407, "Proxy Authentication Required" },
	{ 408, "Request Timeout" },
	{ 409, "Conflict" },
	{ 410, "Gone" },
	{ 411, "Length Required" },
	{ 412, "Precondition Failed" },
	{ 413, "Request Entity Too Large" },
	{ 414, "Request-URI Too Long" },
	{ 415, "Unsupported Media Type" },
	{ 416, "Requested Range Not Satisfiable" },
	{ 417, "Expectation Failed" },
	{ 422, "Unprocessable Entity" }, /* WebDAV */
	{ 423, "Locked" }, /* WebDAV */
	{ 424, "Failed Dependency" }, /* WebDAV */
	{ 426, "Upgrade Required" }, /* TLS */
	{ 500, "Internal Server Error" },
	{ 501, "Not Implemented" },
	{ 502, "Bad Gateway" },
	{ 503, "Service Not Available" },
	{ 504, "Gateway Timeout" },
	{ 505, "HTTP Version Not Supported" },
	{ 507, "Insufficient Storage" }, /* WebDAV */

	{ -1, NULL }
};
#endif

static keyvalue http_status_body[] = {
	"400.html" ,
	"401.html" ,
	"403.html" ,
	"404.html" ,
	"411.html" ,
	"416.html" ,
	"500.html" ,
	"501.html" ,
	"503.html" ,
	"505.html" ,

	NULL
};
/*remove the function of keyvalue_get_value,  We add a new function
 * keyvalue_get_value_by_keyvalue_t(keyvalue *kv, int k, keyvalue_t kt)
 * It perform Efficiency.Time complexity is O (1)*/
const char *keyvalue_get_value_by_keyvalue_t(keyvalue *kv, int k, keyvalue_t kt)
{
	if (kv[k-kt])
		return kv[k-kt];
	return NULL;
}
#if 0
const char *keyvalue_get_value(keyvalue *kv, int k) {
	int i;
	for (i = 0; kv[i].value; i++) {
		if (kv[i].key == k) return kv[i].value;
	}
	return NULL;
}
#endif

/*remove the function of keyvalue_get_key,  We add a new function
 * keyvalue_get_key_by_keyvalue_t(keyvalue *kv, const char *s, keyvalue_t kt)*/
int keyvalue_get_key_by_keyvalue_t(keyvalue *kv, const char *s, keyvalue_t kt) {
	int i;
	for (i = 0; kv[i]; i++) {
		if (0 == strcmp(kv[i], s)) return ( i + kt );
	}
	return -1;
}
#if 0
int keyvalue_get_key(keyvalue *kv, const char *s) {
	int i;
	for (i = 0; kv[i].value; i++) {
		if (0 == strcmp(kv[i].value, s)) return kv[i].key;
	}
	return -1;
}
#endif

/*Since we never used the keyvalue_buffer, So we remove all of them directly.*/
#if 0
keyvalue_buffer *keyvalue_buffer_init(void) {
	keyvalue_buffer *kvb;

	kvb = calloc(1, sizeof(*kvb));

	return kvb;
}

int keyvalue_buffer_append(keyvalue_buffer *kvb, int key, const char *value) {
	size_t i;
	if (kvb->size == 0) {
		kvb->size = 4;

		kvb->kv = malloc(kvb->size * sizeof(*kvb->kv));

		for(i = 0; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
		}
	} else if (kvb->used == kvb->size) {
		kvb->size += 4;

		kvb->kv = realloc(kvb->kv, kvb->size * sizeof(*kvb->kv));

		for(i = kvb->used; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
		}
	}

	kvb->kv[kvb->used]->key = key;
	kvb->kv[kvb->used]->value = strdup(value);

	kvb->used++;

	return 0;
}

void keyvalue_buffer_free(keyvalue_buffer *kvb) {
	size_t i;

	for (i = 0; i < kvb->size; i++) {
		if (kvb->kv[i]->value) free(kvb->kv[i]->value);
		free(kvb->kv[i]);
	}

	if (kvb->kv) free(kvb->kv);

	free(kvb);
}
#endif

s_keyvalue_buffer *s_keyvalue_buffer_init(void) {
	s_keyvalue_buffer *kvb;

	kvb = calloc(1, sizeof(*kvb));

	return kvb;
}

int s_keyvalue_buffer_append(s_keyvalue_buffer *kvb, const char *key, const char *value) {
	size_t i;
	if (kvb->size == 0) {
		kvb->size = 4;
		kvb->used = 0;

		kvb->kv = malloc(kvb->size * sizeof(*kvb->kv));

		for(i = 0; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
		}
	} else if (kvb->used == kvb->size) {
		kvb->size += 4;

		kvb->kv = realloc(kvb->kv, kvb->size * sizeof(*kvb->kv));

		for(i = kvb->used; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
		}
	}

	kvb->kv[kvb->used]->key = key ? strdup(key) : NULL;
	kvb->kv[kvb->used]->value = strdup(value);

	kvb->used++;

	return 0;
}

void s_keyvalue_buffer_free(s_keyvalue_buffer *kvb) {
	size_t i;

	for (i = 0; i < kvb->size; i++) {
		if (kvb->kv[i]->key) free(kvb->kv[i]->key);
		if (kvb->kv[i]->value) free(kvb->kv[i]->value);
		free(kvb->kv[i]);
	}

	if (kvb->kv) free(kvb->kv);

	free(kvb);
}


httpauth_keyvalue_buffer *httpauth_keyvalue_buffer_init(void) {
	httpauth_keyvalue_buffer *kvb;

	kvb = calloc(1, sizeof(*kvb));

	return kvb;
}

int httpauth_keyvalue_buffer_append(httpauth_keyvalue_buffer *kvb, const char *key, const char *realm, httpauth_type type) {
	size_t i;
	if (kvb->size == 0) {
		kvb->size = 4;

		kvb->kv = malloc(kvb->size * sizeof(*kvb->kv));

		for(i = 0; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
		}
	} else if (kvb->used == kvb->size) {
		kvb->size += 4;

		kvb->kv = realloc(kvb->kv, kvb->size * sizeof(*kvb->kv));

		for(i = kvb->used; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
		}
	}

	kvb->kv[kvb->used]->key = strdup(key);
	kvb->kv[kvb->used]->realm = strdup(realm);
	kvb->kv[kvb->used]->type = type;

	kvb->used++;

	return 0;
}

void httpauth_keyvalue_buffer_free(httpauth_keyvalue_buffer *kvb) {
	size_t i;

	for (i = 0; i < kvb->size; i++) {
		if (kvb->kv[i]->key) free(kvb->kv[i]->key);
		if (kvb->kv[i]->realm) free(kvb->kv[i]->realm);
		free(kvb->kv[i]);
	}

	if (kvb->kv) free(kvb->kv);

	free(kvb);
}


const char *get_http_version_name(int i) {
	return keyvalue_get_value_by_keyvalue_t(http_versions, i, HTTP_VERSIONS);
}

const char *get_http_status_name(int i) {
	return keyvalue_get_value_by_keyvalue_t(http_status, i, HTTP_STATUS);
}

const char *get_http_method_name(http_method_t i) {
	return keyvalue_get_value_by_keyvalue_t(http_methods, i, HTTP_METHODS);
}

const char *get_http_status_body_name(int i) {
	return keyvalue_get_value_by_keyvalue_t(http_status_body, i, HTTP_STATUS_BODY);
}

int get_http_version_key(const char *s) {
	return keyvalue_get_key_by_keyvalue_t(http_versions, s, HTTP_VERSIONS);
}

http_method_t get_http_method_key(const char *s) {
	return (http_method_t)keyvalue_get_key_by_keyvalue_t(http_methods, s, HTTP_METHODS);
}




pcre_keyvalue_buffer *pcre_keyvalue_buffer_init(void) {
	pcre_keyvalue_buffer *kvb;

	kvb = calloc(1, sizeof(*kvb));

	return kvb;
}

int pcre_keyvalue_buffer_append(server *srv, pcre_keyvalue_buffer *kvb, const char *key, const char *value) {
#ifdef HAVE_PCRE_H
	size_t i;
	const char *errptr;
	int erroff;
	pcre_keyvalue *kv;
#endif

	if (!key) return -1;

#ifdef HAVE_PCRE_H
	if (kvb->size == 0) {
		kvb->size = 4;
		kvb->used = 0;

		kvb->kv = malloc(kvb->size * sizeof(*kvb->kv));

		for(i = 0; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
		}
	} else if (kvb->used == kvb->size) {
		kvb->size += 4;

		kvb->kv = realloc(kvb->kv, kvb->size * sizeof(*kvb->kv));

		for(i = kvb->used; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
		}
	}

	kv = kvb->kv[kvb->used];
	if (NULL == (kv->key = pcre_compile(key,
					  0, &errptr, &erroff, NULL))) {

		log_error_write(srv, __FILE__, __LINE__, "SS",
			"rexexp compilation error at ", errptr);
		return -1;
	}

	if (NULL == (kv->key_extra = pcre_study(kv->key, 0, &errptr)) &&
			errptr != NULL) {
		return -1;
	}

	kv->value = buffer_init_string(value);

	kvb->used++;

	return 0;
#else
	UNUSED(kvb);
	UNUSED(value);

	return -1;
#endif
}

void pcre_keyvalue_buffer_free(pcre_keyvalue_buffer *kvb) {
#ifdef HAVE_PCRE_H
	size_t i;
	pcre_keyvalue *kv;

	for (i = 0; i < kvb->size; i++) {
		kv = kvb->kv[i];
		if (kv->key) pcre_free(kv->key);
		if (kv->key_extra) pcre_free(kv->key_extra);
		if (kv->value) buffer_free(kv->value);
		free(kv);
	}

	if (kvb->kv) free(kvb->kv);
#endif

	free(kvb);
}
