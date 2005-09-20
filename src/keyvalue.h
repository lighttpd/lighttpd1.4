#ifndef _KEY_VALUE_H_
#define _KEY_VALUE_H_

#include "config.h"

#ifdef HAVE_PCRE_H
# include <pcre.h>
#endif

typedef enum { HTTP_METHOD_UNSET = -1, HTTP_METHOD_GET, HTTP_METHOD_POST, HTTP_METHOD_HEAD, HTTP_METHOD_PROPFIND, HTTP_METHOD_OPTIONS, HTTP_METHOD_MKCOL, HTTP_METHOD_PUT, HTTP_METHOD_DELETE, HTTP_METHOD_COPY, HTTP_METHOD_MOVE, HTTP_METHOD_PROPPATCH, HTTP_METHOD_REPORT } http_method_t;
typedef enum { HTTP_VERSION_UNSET = -1, HTTP_VERSION_1_0, HTTP_VERSION_1_1 } http_version_t;

typedef struct {
	int key;
	
	char *value;
} keyvalue;

typedef struct {
	char *key;
	
	char *value;
} s_keyvalue;

typedef struct {
#ifdef HAVE_PCRE_H
	pcre *key;
	pcre_extra *key_extra;
#endif
	
	buffer *value;
} pcre_keyvalue;

typedef enum { HTTP_AUTH_BASIC, HTTP_AUTH_DIGEST } httpauth_type;

typedef struct {
	char *key;
	
	char *realm;
	httpauth_type type;
} httpauth_keyvalue;

#define KVB(x) \
typedef struct {\
	x **kv; \
	size_t used;\
	size_t size;\
} x ## _buffer

KVB(keyvalue);
KVB(s_keyvalue);
KVB(httpauth_keyvalue);
KVB(pcre_keyvalue);

const char *get_http_status_name(int i);
const char *get_http_version_name(int i);
const char *get_http_method_name(http_method_t i);
const char *get_http_status_body_name(int i);
int get_http_version_key(const char *s);
http_method_t get_http_method_key(const char *s);

const char *keyvalue_get_value(keyvalue *kv, int k);
int keyvalue_get_key(keyvalue *kv, const char *s);

keyvalue_buffer *keyvalue_buffer_init(void);
int keyvalue_buffer_append(keyvalue_buffer *kvb, int k, const char *value);
void keyvalue_buffer_free(keyvalue_buffer *kvb);

s_keyvalue_buffer *s_keyvalue_buffer_init(void);
int s_keyvalue_buffer_append(s_keyvalue_buffer *kvb, const char *key, const char *value);
void s_keyvalue_buffer_free(s_keyvalue_buffer *kvb);

httpauth_keyvalue_buffer *httpauth_keyvalue_buffer_init(void);
int httpauth_keyvalue_buffer_append(httpauth_keyvalue_buffer *kvb, const char *key, const char *realm, httpauth_type type);
void httpauth_keyvalue_buffer_free(httpauth_keyvalue_buffer *kvb);

pcre_keyvalue_buffer *pcre_keyvalue_buffer_init(void);
int pcre_keyvalue_buffer_append(pcre_keyvalue_buffer *kvb, const char *key, const char *value);
void pcre_keyvalue_buffer_free(pcre_keyvalue_buffer *kvb);

#endif
