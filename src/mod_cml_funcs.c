#include <sys/stat.h>
#include <time.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include "buffer.h"
#include "server.h"
#include "log.h"
#include "plugin.h"
#include "response.h"

#include "mod_cml.h"

#ifdef USE_OPENSSL
# include <openssl/md5.h>
#else
# include "md5_global.h"
# include "md5.h"
#endif

#define HASHLEN 16
typedef unsigned char HASH[HASHLEN];
#define HASHHEXLEN 32
typedef char HASHHEX[HASHHEXLEN+1];
#ifdef USE_OPENSSL
#define IN const
#else
#define IN 
#endif
#define OUT

CACHE_FUNC_PROTO(f_unix_time_now) {
	UNUSED(srv);
	UNUSED(con);
	UNUSED(p);
	
	VAL_LONG(result) = srv->cur_ts;
	
	return 0;
}

CACHE_FUNC_PROTO(f_file_mtime) {
	buffer *b;
	struct stat st;
	
	UNUSED(con);
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_file_mtime: I need a string:", 
				p->params->ptr[0]->type);
		
		return -1;
	}
	
	b = buffer_init();
			
	/* build filename */
	buffer_copy_string_buffer(b, p->basedir);
	buffer_append_string_buffer(b, p->params->ptr[0]->data.str);
	
	if (-1 == stat(b->ptr, &st)) {
		log_error_write(srv, __FILE__, __LINE__, "sbs", 
				"trigger.if file.mtime():", b, strerror(errno));
		
		buffer_free(b);
		return -1;
	}
	buffer_free(b);
	
	tnode_prepare_long(result);
	VAL_LONG(result) = st.st_mtime;
	
	return 0;
}

int split_query_string(server *srv, connection *con, array *vals) {
	size_t key_start = 0, key_end = 0, 
		value_start = 0;
	size_t is_key = 1;
	size_t i;
	
	for (i = 0; i < con->uri.query->used; i++) {
		switch(con->uri.query->ptr[i]) {
		case '=':
			if (is_key) {
				key_end = i - 1;
				value_start = i + 1;
				
				is_key = 0;
			}
			
			break;
		case '&':
		case '\0': /* fin symbol */
			if (!is_key) {
				data_string *ds;
				
				/* we need at least a = since the last & */
				
				if (NULL == (ds = (data_string *)array_get_unused_element(vals, TYPE_STRING))) {
					ds = data_string_init();
				}
				
				buffer_copy_string_len(ds->key,   con->uri.query->ptr + key_start, key_end - key_start);
				buffer_copy_string_len(ds->value, con->uri.query->ptr + value_start, i - value_start);
				
				array_insert_unique(vals, (data_unset *)ds);
			}
			
			key_start = i + 1;
			value_start = 0;
			is_key = 1;
			break;
		}
	}
	
	return 0;
}


CACHE_FUNC_PROTO(f_http_request_get_param) {
	array *qry_str;
	data_string *ds;
	
	/* fetch data from the con-> request query string */
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_http_request_get_param: I need a string:", 
				p->params->ptr[0]->type);
		
		return -1;
	}
	
	qry_str = array_init();
	
	split_query_string(srv, con, qry_str);
	
	tnode_prepare_string(result);
	
	if (NULL == (ds = (data_string *)array_get_element(qry_str, p->params->ptr[0]->data.str->ptr))) {
		
		buffer_copy_string(VAL_STRING(result), "");
		
		array_free(qry_str);
		
		return 0;
	}
	
	buffer_copy_string_buffer(VAL_STRING(result), ds->value);
	
	array_free(qry_str);
	
	return 0;
}

CACHE_FUNC_PROTO(f_crypto_md5) {
	MD5_CTX Md5Ctx;
	HASH HA1;
	
	/* fetch data from the con-> request query string */
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"crypto.md5: I need a string:", 
				p->params->ptr[0]->type);
		
		return -1;
	}
	
	MD5_Init(&Md5Ctx);
	MD5_Update(&Md5Ctx, (unsigned char *)p->params->ptr[0]->data.str->ptr, p->params->ptr[0]->data.str->used - 1);
	MD5_Final(HA1, &Md5Ctx);
	
	tnode_prepare_string(result);
	buffer_copy_string_hex(VAL_STRING(result), (char *)HA1, 16);
	
	return 0;
}

#ifdef HAVE_MEMCACHE_H
CACHE_FUNC_PROTO(f_memcache_exists) {
	char *r;
	
	UNUSED(con);
	
	if (!p->conf.mc) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_exists: no memcache.hosts set:", 
				p->params->ptr[0]->type);
		return -1;
	}
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_exists: I need a string:", 
				p->params->ptr[0]->type);
		
		return -1;
	}
	
	tnode_prepare_long(result);
	
	if (NULL == (r = mc_aget(p->conf.mc, 
				 CONST_BUF_LEN(p->params->ptr[0]->data.str)))) {
				
		VAL_LONG(result) = 0;
		return 0;
	}
	
	free(r);
	
	VAL_LONG(result) = 1;
	
	return 0;
}

CACHE_FUNC_PROTO(f_memcache_get_string) {
	char *r;
	
	UNUSED(con);
	
	if (!p->conf.mc) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_get_string: no memcache.hosts set:", 
				p->params->ptr[0]->type);
		return -1;
	}
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_get_string: I need a string:", 
				p->params->ptr[0]->type);
		return -1;
	}
	
	if (NULL == (r = mc_aget(p->conf.mc, 
				 p->params->ptr[0]->data.str->ptr, p->params->ptr[0]->data.str->used - 1))) {
		log_error_write(srv, __FILE__, __LINE__, "sb", 
				"f_memcache_get_string: couldn't find:", 
				p->params->ptr[0]->data.str);
		return -1;
	}
	tnode_prepare_string(result);
	buffer_copy_string(VAL_STRING(result), r);
	
	free(r);
	
	return 0;
}

CACHE_FUNC_PROTO(f_memcache_get_long) {
	char *r;
	
	UNUSED(con);
	
	if (!p->conf.mc) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_get_long: no memcache.hosts set:", 
				p->params->ptr[0]->type);
		return -1;
	}
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_get_long: I need a string:", 
				p->params->ptr[0]->type);
		return -1;
	}
	
	if (NULL == (r = mc_aget(p->conf.mc, 
				 CONST_BUF_LEN(p->params->ptr[0]->data.str)))) {
		log_error_write(srv, __FILE__, __LINE__, "sb", 
				"f_memcache_get_long: couldn't find:", 
				p->params->ptr[0]->data.str);
		return -1;
	}
	
	tnode_prepare_long(result);
	VAL_LONG(result) = strtol(r, NULL, 10);
	
	free(r);
	
	return 0;
}
#endif
