#include <string.h>
#include <errno.h>

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "log.h"

int response_header_insert(server *srv, connection *con, const char *key, size_t keylen, const char *value, size_t vallen) {
	data_string *ds;
	
	UNUSED(srv);

	if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
		ds = data_response_init();
	}
	buffer_copy_string_len(ds->key, key, keylen);
	buffer_copy_string_len(ds->value, value, vallen);
	
	array_insert_unique(con->response.headers, (data_unset *)ds);
	
	return 0;
}

int response_header_overwrite(server *srv, connection *con, const char *key, size_t keylen, const char *value, size_t vallen) {
	data_string *ds;
	
	UNUSED(srv);

	/* if there already is a key by this name overwrite the value */
	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, key))) {
		buffer_copy_string(ds->value, value);
		
		return 0;
	}
	
	return response_header_insert(srv, con, key, keylen, value, vallen);
}

int http_response_redirect_to_directory(server *srv, connection *con) {
	buffer *o;
	
	o = buffer_init();
	
	if (con->conf.is_ssl) {
		buffer_copy_string(o, "https://");
	} else {
		buffer_copy_string(o, "http://");
	}
	if (con->uri.authority->used) {
		buffer_append_string_buffer(o, con->uri.authority);
	} else {
		/* get the name of the currently connected socket */
		struct hostent *he;
#ifdef HAVE_IPV6
		char hbuf[256];
#endif
		sock_addr our_addr;
		socklen_t our_addr_len;
		
		our_addr_len = sizeof(our_addr);
		
		if (-1 == getsockname(con->fd, &(our_addr.plain), &our_addr_len)) {
			con->http_status = 500;
			
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"can't get sockname", strerror(errno));
			
			buffer_free(o);
			return 0;
		}
		
		
		/* Lookup name: secondly try to get hostname for bind address */
		switch(our_addr.plain.sa_family) {
#ifdef HAVE_IPV6
		case AF_INET6:
			if (0 != getnameinfo((const struct sockaddr *)(&our_addr.ipv6), 
					     SA_LEN((const struct sockaddr *)&our_addr.ipv6), 
					     hbuf, sizeof(hbuf), NULL, 0, 0)) {
				
				char dst[INET6_ADDRSTRLEN];
				
				log_error_write(srv, __FILE__, __LINE__,
						"SSSS", "NOTICE: getnameinfo failed: ",
						strerror(errno), ", using ip-address instead");
				
				buffer_append_string(o, 
						     inet_ntop(AF_INET6, (char *)&our_addr.ipv6.sin6_addr, 
							       dst, sizeof(dst)));
			} else {
				buffer_append_string(o, hbuf);
			}
			break;
#endif
		case AF_INET:
			if (NULL == (he = gethostbyaddr((char *)&our_addr.ipv4.sin_addr, sizeof(struct in_addr), AF_INET))) {
				log_error_write(srv, __FILE__, __LINE__,
						"SSSS", "NOTICE: gethostbyaddr failed: ",
						hstrerror(h_errno), ", using ip-address instead");
				
				buffer_append_string(o, inet_ntoa(our_addr.ipv4.sin_addr));
			} else {
				buffer_append_string(o, he->h_name);
			}
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__,
					"S", "ERROR: unsupported address-type");
			
			buffer_free(o);
			return -1;
		}
		
		if (!((con->conf.is_ssl == 0 && srv->srvconf.port == 80) || 
		      (con->conf.is_ssl == 1 && srv->srvconf.port == 443))) {
			buffer_append_string(o, ":");
			buffer_append_long(o, srv->srvconf.port);
		}
	}
	buffer_append_string_buffer(o, con->uri.path);
	buffer_append_string(o, "/");
	if (!buffer_is_empty(con->uri.query)) {
		buffer_append_string(o, "?");
		buffer_append_string_buffer(o, con->uri.query);
	}
	
	response_header_insert(srv, con, CONST_STR_LEN("Location"), CONST_BUF_LEN(o));
	
	con->http_status = 301;
	
	buffer_free(o);
	
	return 0;
}

