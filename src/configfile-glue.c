
#include "base.h"
#include "buffer.h"
#include "array.h"
#include "log.h"

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
					
				log_error_write(srv, __FILE__, __LINE__, "ssbss", "unexpected type for key: ", cv[i].key, ds->value, "(short)", "0 ... 65535");
				
				return -1;
			}
			default:
				log_error_write(srv, __FILE__, __LINE__, "ssdss", "unexpected type for key: ", cv[i].key, du->type, "(short)", "0 ... 65535");
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

int config_check_cond(server *srv, connection *con, data_config *dc) {
	buffer *l;
	server_socket *srv_sock = con->srv_socket;
	/* pass the rules */
	
	l = srv->empty_string;
	
	if (buffer_is_equal_string(dc->comp_key, CONST_STR_LEN("HTTPhost"))) {
		l = con->uri.authority;
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
		return 0;
	}
	
	switch(dc->cond) {
	case CONFIG_COND_NE:
	case CONFIG_COND_EQ:
		if (buffer_is_equal(l, dc->match.string)) {
			return (dc->cond == CONFIG_COND_EQ) ? 1 : 0;
		} else {
			return (dc->cond == CONFIG_COND_EQ) ? 0 : 1;
		}
		break;
#ifdef HAVE_PCRE_H
	case CONFIG_COND_NOMATCH:
	case CONFIG_COND_MATCH: {
#define N 10
		int ovec[N * 3];
		int n;
		
		n = pcre_exec(dc->match.regex, NULL, l->ptr, l->used - 1, 0, 0, ovec, N * 3);
		
		if (n > 0) {
			return (dc->cond == CONFIG_COND_MATCH) ? 1 : 0;
		} else {
			return (dc->cond == CONFIG_COND_MATCH) ? 0 : 1;
		}
		
		break;
	}
#endif
	default:
		/* no way */
		break;
	}
	
	return 0;
}

