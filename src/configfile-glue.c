
#include "base.h"
#include "buffer.h"
#include "array.h"
#include "log.h"
#include "plugin.h"

/**
 * like all glue code this file contains functions which
 * are the external interface of lighttpd. The functions
 * are used by the server itself and the plugins.
 *
 * The main-goal is to have a small library in the end 
 * which is linked against both and which will define 
 * the interface itself in the end.
 * 
 */


/* handle global options */

/* parse config array */
int config_insert_values_internal(server *srv, array *ca, const config_values_t cv[]) {
	size_t i;
	data_unset *du;
	
	for (i = 0; cv[i].key; i++) {
		
		if (NULL == (du = array_get_element(ca, cv[i].key))) {
			/* no found */
			
			continue;
		}
		
		switch (cv[i].type) {
		case T_CONFIG_ARRAY:
			if (du->type == TYPE_ARRAY) {
				size_t j;
				data_array *da = (data_array *)du;
				
				for (j = 0; j < da->value->used; j++) {
					if (da->value->data[j]->type == TYPE_STRING) {
						data_string *ds = data_string_init();
						
						buffer_copy_string_buffer(ds->value, ((data_string *)(da->value->data[j]))->value);
						buffer_copy_string_buffer(ds->key, ((data_string *)(da->value->data[j]))->key);
						
						array_insert_unique(cv[i].destination, (data_unset *)ds);
					} else {
						log_error_write(srv, __FILE__, __LINE__, "sssbs", "unexpected type for key: ", cv[i].key, "[", da->value->data[i]->key, "](string)");
						
						return -1;
					}
				}
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sss", "unexpected type for key: ", cv[i].key, "array of strings");
				
				return -1;
			}
			break;
		case T_CONFIG_STRING:
			if (du->type == TYPE_STRING) {
				data_string *ds = (data_string *)du;
				
				buffer_copy_string_buffer(cv[i].destination, ds->value);
			} else {
				log_error_write(srv, __FILE__, __LINE__, "ssss", "unexpected type for key: ", cv[i].key, "(string)", "\"...\"");
				
				return -1;
			}
			break;
		case T_CONFIG_SHORT:
			switch(du->type) {
			case TYPE_INTEGER: {
				data_integer *di = (data_integer *)du;
				
				*((unsigned short *)(cv[i].destination)) = di->value;
				break;
			}
			case TYPE_STRING: {
				data_string *ds = (data_string *)du;
					
				log_error_write(srv, __FILE__, __LINE__, "ssb", "get a string but expected a short:", cv[i].key, ds->value);
				
				return -1;
			}
			default:
				log_error_write(srv, __FILE__, __LINE__, "ssds", "unexpected type for key:", cv[i].key, du->type, "expected a integer, range 0 ... 65535");
				return -1;
			}
			break;
		case T_CONFIG_BOOLEAN:
			if (du->type == TYPE_STRING) {
				data_string *ds = (data_string *)du;
				
				if (buffer_is_equal_string(ds->value, CONST_STR_LEN("enable"))) {
					*((unsigned short *)(cv[i].destination)) = 1;
				} else if (buffer_is_equal_string(ds->value, CONST_STR_LEN("disable"))) {
					*((unsigned short *)(cv[i].destination)) = 0;
				} else {
					log_error_write(srv, __FILE__, __LINE__, "ssbs", "ERROR: unexpected value for key:", cv[i].key, ds->value, "(enable|disable)");
						
					return -1;
				}
			} else {
				log_error_write(srv, __FILE__, __LINE__, "ssss", "ERROR: unexpected type for key:", cv[i].key, "(string)", "\"(enable|disable)\"");
				
				return -1;
			}
			break;
		case T_CONFIG_LOCAL:
		case T_CONFIG_UNSET:
			break;
		case T_CONFIG_DEPRECATED:
			log_error_write(srv, __FILE__, __LINE__, "ssss", "ERROR: found deprecated key:", cv[i].key, "-", (char *)(cv[i].destination));
			
			srv->config_deprecated = 1;
			
			break;
		}
	}
	return 0;
}

int config_insert_values_global(server *srv, array *ca, const config_values_t cv[]) {
	size_t i;
	data_unset *du;
	
	for (i = 0; cv[i].key; i++) {
		data_string *touched;
		
		if (NULL == (du = array_get_element(ca, cv[i].key))) {
			/* no found */
			
			continue;
		}
		
		/* touched */
		touched = data_string_init();
		
		buffer_copy_string(touched->value, "");
		buffer_copy_string_buffer(touched->key, du->key);
		
		array_insert_unique(srv->config_touched, (data_unset *)touched);
	}
	
	return config_insert_values_internal(srv, ca, cv);
}

static int config_check_cond_cached(server *srv, connection *con, data_config *dc);

static cond_result_t config_check_cond_nocache(server *srv, connection *con, data_config *dc) {
	buffer *l;
	server_socket *srv_sock = con->srv_socket;
	/* check parent first */
	if (dc->parent && dc->parent->context_ndx) {
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "sb", "go parent", dc->parent->string);
		}
		if (!config_check_cond_cached(srv, con, dc->parent)) {
			return COND_RESULT_FALSE;
		}
	}

	if (dc->prev) {
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "sb", "go prev", dc->prev->string);
		}
		/* make sure prev is checked first */
		config_check_cond_cached(srv, con, dc->prev);
		/* one of prev set me to FALSE */
		if (con->cond_results_cache[dc->context_ndx] == COND_RESULT_FALSE) {
			return COND_RESULT_FALSE;
		}
	}

	/* 
	 * OPTIMIZE
	 * 
	 * - replace all is_equal be simple == to an enum
	 * 
	 */

	/* pass the rules */
	
	l = srv->empty_string;
	
	if (buffer_is_equal_string(dc->comp_key, CONST_STR_LEN("HTTPhost"))) {
		l = con->uri.authority;
#if 0
		/* FIXME: get this working again */
		char *ck_colon = NULL, *val_colon = NULL;
		
		if (!buffer_is_empty(con->uri.authority)) {
		
			/* 
			 * append server-port to the HTTP_POST if necessary
			 */
			
			buffer_copy_string_buffer(srv->cond_check_buf, con->uri.authority);
			
			switch(dc->cond) {
			case CONFIG_COND_NE:
			case CONFIG_COND_EQ:
				ck_colon = strchr(dc->string->ptr, ':');
				val_colon = strchr(con->uri.authority->ptr, ':');
				
				if (ck_colon && !val_colon) {
					/* colon found */
					BUFFER_APPEND_STRING_CONST(srv->cond_check_buf, ":");
					buffer_append_long(srv->cond_check_buf, sock_addr_get_port(&(srv_sock->addr)));
				}
				break;
			default:
				break;
			}
		}
	} else if (buffer_is_equal_string(dc->comp_key, CONST_STR_LEN("HTTPremoteip"))) {
		char *nm_slash;
		/* handle remoteip limitations 
		 * 
		 * "10.0.0.1" is provided for all comparisions
		 * 
		 * only for == and != we support
		 * 
		 * "10.0.0.1/24"
		 */
		
		if ((dc->cond == CONFIG_COND_EQ ||
		     dc->cond == CONFIG_COND_NE) &&
		    (con->dst_addr.plain.sa_family == AF_INET) &&
		    (NULL != (nm_slash = strchr(dc->string->ptr, '/')))) {
			int nm_bits;
			long nm;
			char *err;
			struct in_addr val_inp;
			
			if (*(nm_slash+1) == '\0') {
				log_error_write(srv, __FILE__, __LINE__, "sb", "ERROR: no number after / ", dc->string);
					
				return COND_RESULT_FALSE;
			}
			
			nm_bits = strtol(nm_slash + 1, &err, 10);
			
			if (*err) {
				log_error_write(srv, __FILE__, __LINE__, "sbs", "ERROR: non-digit found in netmask:", dc->string, *err);
				
				return COND_RESULT_FALSE;
			}
			
			/* take IP convert to the native */
			buffer_copy_string_len(srv->cond_check_buf, dc->string->ptr, nm_slash - dc->string->ptr);
#ifdef __WIN32			
			if (INADDR_NONE == (val_inp.s_addr = inet_addr(srv->cond_check_buf->ptr))) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "ERROR: ip addr is invalid:", srv->cond_check_buf);
				
				return COND_RESULT_FALSE;
			}

#else
			if (0 == inet_aton(srv->cond_check_buf->ptr, &val_inp)) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "ERROR: ip addr is invalid:", srv->cond_check_buf);
				
				return COND_RESULT_FALSE;
			}
#endif
			
			/* build netmask */
			nm = htonl(~((1 << (32 - nm_bits)) - 1));
			
			if ((val_inp.s_addr & nm) == (con->dst_addr.ipv4.sin_addr.s_addr & nm)) {
				return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
			} else {
				return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
			}
		} else {
			const char *s;
#ifdef HAVE_IPV6
			char b2[INET6_ADDRSTRLEN + 1];
			
			s = inet_ntop(con->dst_addr.plain.sa_family, 
				      con->dst_addr.plain.sa_family == AF_INET6 ? 
				      (const void *) &(con->dst_addr.ipv6.sin6_addr) :
				      (const void *) &(con->dst_addr.ipv4.sin_addr),
				      b2, sizeof(b2)-1);
#else
			s = inet_ntoa(con->dst_addr.ipv4.sin_addr);
#endif
			buffer_copy_string(srv->cond_check_buf, s);
		}
#endif
	} else if (buffer_is_equal_string(dc->comp_key, CONST_STR_LEN("HTTPurl"))) {
		l = con->uri.path;
	} else if (buffer_is_equal_string(dc->comp_key, CONST_STR_LEN("SERVERsocket"))) {
		l = srv_sock->srv_token;
	} else if (buffer_is_equal_string(dc->comp_key, CONST_STR_LEN("HTTPreferer"))) {
		data_string *ds;
		
		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Referer"))) {
			l = ds->value;
		}
	} else if (buffer_is_equal_string(dc->comp_key, CONST_STR_LEN("HTTPcookie"))) {
		data_string *ds;
		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Cookie"))) {
			l = ds->value;
		}
	} else if (buffer_is_equal_string(dc->comp_key, CONST_STR_LEN("HTTPuseragent"))) {
		data_string *ds;
		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "User-Agent"))) {
			l = ds->value;
		}
	} else {
		return COND_RESULT_FALSE;
	}
	
	if (con->conf.log_condition_handling) {
		log_error_write(srv, __FILE__, __LINE__,  "bsbsb", dc->comp_key, "(", l, ") compare to ", dc->string);
	}
	switch(dc->cond) {
	case CONFIG_COND_NE:
	case CONFIG_COND_EQ:
		if (buffer_is_equal(l, dc->string)) {
			return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
		} else {
			return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
		}
		break;
#ifdef HAVE_PCRE_H
	case CONFIG_COND_NOMATCH:
	case CONFIG_COND_MATCH: {
#define N 10
		int ovec[N * 3];
		int n;
		
		n = pcre_exec(dc->regex, dc->regex_study, l->ptr, l->used - 1, 0, 0, ovec, N * 3);
		
		if (n > 0) {
			return (dc->cond == CONFIG_COND_MATCH) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
		} else {
			return (dc->cond == CONFIG_COND_MATCH) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
		}
		break;
	}
#endif
	default:
		/* no way */
		break;
	}
	
	return COND_RESULT_FALSE;
}

static int config_check_cond_cached(server *srv, connection *con, data_config *dc) {
	cond_result_t *cache = con->cond_results_cache;

	if (cache[dc->context_ndx] == COND_RESULT_UNSET) {
		if (COND_RESULT_TRUE == (cache[dc->context_ndx] = config_check_cond_nocache(srv, con, dc))) {
			if (dc->next) {
				data_config *c;
				if (con->conf.log_condition_handling) {
					log_error_write(srv, __FILE__, __LINE__, "s", "setting remains of chaining to FALSE");
				}
				for (c = dc->next; c; c = c->next) {
					cache[c->context_ndx] = COND_RESULT_FALSE;
				}
			}
		}
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__, "dsd", dc->context_ndx, "(uncached) result:", cache[dc->context_ndx]);
		}
	}
	else {
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__, "dsd", dc->context_ndx, "(cached) result:", cache[dc->context_ndx]);
		}
	}
	return cache[dc->context_ndx];
}

int config_check_cond(server *srv, connection *con, data_config *dc) {
	if (con->conf.log_condition_handling) {
		log_error_write(srv, __FILE__, __LINE__,  "s",  "=== start of condition block ===");
	}
	return config_check_cond_cached(srv, con, dc);
}
