#include "first.h"

#include "request.h"
#include "base.h"
#include "burl.h"
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "sock_addr.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int request_check_hostname(buffer *host) {
	enum { DOMAINLABEL, TOPLABEL } stage = TOPLABEL;
	size_t i;
	int label_len = 0;
	size_t host_len, hostport_len;
	char *colon;
	int is_ip = -1; /* -1 don't know yet, 0 no, 1 yes */
	int level = 0;

	/*
	 *       hostport      = host [ ":" port ]
	 *       host          = hostname | IPv4address | IPv6address
	 *       hostname      = *( domainlabel "." ) toplabel [ "." ]
	 *       domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum
	 *       toplabel      = alpha | alpha *( alphanum | "-" ) alphanum
	 *       IPv4address   = 1*digit "." 1*digit "." 1*digit "." 1*digit
	 *       IPv6address   = "[" ... "]"
	 *       port          = *digit
	 */

	/* IPv6 adress */
	if (host->ptr[0] == '[') {
		char *c = host->ptr + 1;
		int colon_cnt = 0;

		/* check the address inside [...] */
		for (; *c && *c != ']'; c++) {
			if (*c == ':') {
				if (++colon_cnt > 7) {
					return -1;
				}
			} else if (!light_isxdigit(*c) && '.' != *c) {
				return -1;
			}
		}

		/* missing ] */
		if (!*c) {
			return -1;
		}

		/* check port */
		if (*(c+1) == ':') {
			for (c += 2; *c; c++) {
				if (!light_isdigit(*c)) {
					return -1;
				}
			}
		}
		else if ('\0' != *(c+1)) {
			/* only a port is allowed to follow [...] */
			return -1;
		}
		return 0;
	}

	hostport_len = host_len = buffer_string_length(host);

	if (NULL != (colon = memchr(host->ptr, ':', host_len))) {
		char *c = colon + 1;

		/* check portnumber */
		for (; *c; c++) {
			if (!light_isdigit(*c)) return -1;
		}

		/* remove the port from the host-len */
		host_len = colon - host->ptr;
	}

	/* Host is empty */
	if (host_len == 0) return -1;

	/* if the hostname ends in a "." strip it */
	if (host->ptr[host_len-1] == '.') {
		/* shift port info one left */
		if (NULL != colon) memmove(colon-1, colon, hostport_len - host_len);
		buffer_string_set_length(host, --hostport_len);
		if (--host_len == 0) return -1;
	}


	/* scan from the right and skip the \0 */
	for (i = host_len; i-- > 0; ) {
		const char c = host->ptr[i];

		switch (stage) {
		case TOPLABEL:
			if (c == '.') {
				/* only switch stage, if this is not the last character */
				if (i != host_len - 1) {
					if (label_len == 0) {
						return -1;
					}

					/* check the first character at right of the dot */
					if (is_ip == 0) {
						if (!light_isalnum(host->ptr[i+1])) {
							return -1;
						}
					} else if (!light_isdigit(host->ptr[i+1])) {
						is_ip = 0;
					} else if ('-' == host->ptr[i+1]) {
						return -1;
					} else {
						/* just digits */
						is_ip = 1;
					}

					stage = DOMAINLABEL;

					label_len = 0;
					level++;
				} else if (i == 0) {
					/* just a dot and nothing else is evil */
					return -1;
				}
			} else if (i == 0) {
				/* the first character of the hostname */
				if (!light_isalnum(c)) {
					return -1;
				}
				label_len++;
			} else {
				if (c != '-' && !light_isalnum(c)) {
					return -1;
				}
				if (is_ip == -1) {
					if (!light_isdigit(c)) is_ip = 0;
				}
				label_len++;
			}

			break;
		case DOMAINLABEL:
			if (is_ip == 1) {
				if (c == '.') {
					if (label_len == 0) {
						return -1;
					}

					label_len = 0;
					level++;
				} else if (!light_isdigit(c)) {
					return -1;
				} else {
					label_len++;
				}
			} else {
				if (c == '.') {
					if (label_len == 0) {
						return -1;
					}

					/* c is either - or alphanum here */
					if ('-' == host->ptr[i+1]) {
						return -1;
					}

					label_len = 0;
					level++;
				} else if (i == 0) {
					if (!light_isalnum(c)) {
						return -1;
					}
					label_len++;
				} else {
					if (c != '-' && !light_isalnum(c)) {
						return -1;
					}
					label_len++;
				}
			}

			break;
		}
	}

	/* a IP has to consist of 4 parts */
	if (is_ip == 1 && level != 3) {
		return -1;
	}

	if (label_len == 0) {
		return -1;
	}

	return 0;
}

int http_request_host_normalize(buffer *b, int scheme_port) {
    /*
     * check for and canonicalize numeric IP address and portnum (optional)
     * (IP address may be followed by ":portnum" (optional))
     * - IPv6: "[...]"
     * - IPv4: "x.x.x.x"
     * - IPv4: 12345678   (32-bit decimal number)
     * - IPv4: 012345678  (32-bit octal number)
     * - IPv4: 0x12345678 (32-bit hex number)
     *
     * allow any chars (except ':' and '\0' and stray '[' or ']')
     *   (other code may check chars more strictly or more pedantically)
     * ':'  delimits (optional) port at end of string
     * "[]" wraps IPv6 address literal
     * '\0' should have been rejected earlier were it present
     *
     * any chars includes, but is not limited to:
     * - allow '-' any where, even at beginning of word
     *     (security caution: might be confused for cmd flag if passed to shell)
     * - allow all-digit TLDs
     *     (might be mistaken for IPv4 addr by inet_aton()
     *      unless non-digits appear in subdomain)
     */

    /* Note: not using getaddrinfo() since it does not support "[]" around IPv6
     * and is not as lenient as inet_aton() and inet_addr() for IPv4 strings.
     * Not using inet_pton() (when available) on IPv4 for similar reasons. */

    const char * const p = b->ptr;
    const size_t blen = buffer_string_length(b);
    long port = 0;

    if (*p != '[') {
        char * const colon = (char *)memchr(p, ':', blen);
        if (colon) {
            if (*p == ':') return -1; /*(empty host then port, or naked IPv6)*/
            if (colon[1] != '\0') {
                char *e;
                port = strtol(colon+1, &e, 0); /*(allow decimal, octal, hex)*/
                if (0 < port && port <= USHRT_MAX && *e == '\0') {
                    /* valid port */
                } else {
                    return -1;
                }
            } /*(else ignore stray colon at string end)*/
            buffer_string_set_length(b, (size_t)(colon - p)); /*(remove port str)*/
        }

        if (light_isdigit(*p)) do {
            /* (IPv4 address literal or domain starting w/ digit (e.g. 3com))*/
            /* (check one-element cache of normalized IPv4 address string) */
            static struct { char s[INET_ADDRSTRLEN]; size_t n; } laddr;
            size_t n = colon ? (size_t)(colon - p) : blen;
            sock_addr addr;
            if (n == laddr.n && 0 == memcmp(p, laddr.s, n)) break;
            if (1 == sock_addr_inet_pton(&addr, p, AF_INET, 0)) {
                sock_addr_inet_ntop_copy_buffer(b, &addr);
                n = buffer_string_length(b);
                if (n < sizeof(laddr.s)) memcpy(laddr.s, b->ptr, (laddr.n = n));
            }
        } while (0);
    } else do { /* IPv6 addr */
      #if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)

        /* (check one-element cache of normalized IPv4 address string) */
        static struct { char s[INET6_ADDRSTRLEN]; size_t n; } laddr;
        sock_addr addr;
        char *bracket = b->ptr+blen-1;
        char *percent = strchr(b->ptr+1, '%');
        size_t len;
        int rc;
        char buf[INET6_ADDRSTRLEN+16]; /*(+16 for potential %interface name)*/
        if (blen <= 2) return -1; /*(invalid "[]")*/
        if (*bracket != ']') {
            bracket = (char *)memchr(b->ptr+1, ']', blen-1);
            if (NULL == bracket || bracket[1] != ':'  || bracket - b->ptr == 1){
               return -1;
            }
            if (bracket[2] != '\0') { /*(ignore stray colon at string end)*/
                char *e;
                port = strtol(bracket+2, &e, 0); /*(allow decimal, octal, hex)*/
                if (0 < port && port <= USHRT_MAX && *e == '\0') {
                    /* valid port */
                } else {
                    return -1;
                }
            }
        }

        len = (size_t)((percent ? percent : bracket) - (b->ptr+1));
        if (laddr.n == len && 0 == memcmp(laddr.s, b->ptr+1, len)) {
            /* truncate after ']' and re-add normalized port, if needed */
            buffer_string_set_length(b, (size_t)(bracket - b->ptr + 1));
            break;
        }

        *bracket = '\0';/*(terminate IPv6 string)*/
        if (percent) *percent = '\0'; /*(remove %interface from address)*/
        rc = sock_addr_inet_pton(&addr, b->ptr+1, AF_INET6, 0);
        if (percent) *percent = '%'; /*(restore %interface)*/
        *bracket = ']'; /*(restore bracket)*/
        if (1 != rc) return -1;

        sock_addr_inet_ntop(&addr, buf, sizeof(buf));
        len = strlen(buf);
        if (percent) {
            if (percent > bracket) return -1;
            if (len + (size_t)(bracket - percent) >= sizeof(buf)) return -1;
            if (len < sizeof(laddr.s)) memcpy(laddr.s, buf, (laddr.n = len));
            memcpy(buf+len, percent, (size_t)(bracket - percent));
            len += (size_t)(bracket - percent);
        }
        buffer_string_set_length(b, 1); /* truncate after '[' */
        buffer_append_string_len(b, buf, len);
        buffer_append_string_len(b, CONST_STR_LEN("]"));

      #else

        return -1;

      #endif
    } while (0);

    if (0 != port && port != scheme_port) {
        buffer_append_string_len(b, CONST_STR_LEN(":"));
        buffer_append_int(b, (int)port);
    }

    return 0;
}

static int scheme_port (const buffer *scheme)
{
    return buffer_is_equal_string(scheme, CONST_STR_LEN("https")) ? 443 : 80;
}

int http_request_host_policy (connection *con, buffer *b, const buffer *scheme) {
    return (((con->conf.http_parseopts & HTTP_PARSEOPT_HOST_STRICT)
             && 0 != request_check_hostname(b))
            || ((con->conf.http_parseopts & HTTP_PARSEOPT_HOST_NORMALIZE)
                && 0 != http_request_host_normalize(b, scheme_port(scheme))));
}

static int http_request_split_value(array *vals, const char *current, size_t len) {
	int state = 0;
	const char *token_start = NULL, *token_end = NULL;
	/*
	 * parse
	 *
	 * val1, val2, val3, val4
	 *
	 * into a array (more or less a explode() incl. stripping of whitespaces
	 */

	for (size_t i = 0; i <= len; ++i, ++current) {
		switch (state) {
		case 0: /* find start of a token */
			switch (*current) {
			case ' ':
			case '\t': /* skip white space */
			case ',': /* skip empty token */
				break;
			case '\0': /* end of string */
				return 0;
			default:
				/* found real data, switch to state 1 to find the end of the token */
				token_start = token_end = current;
				state = 1;
				break;
			}
			break;
		case 1: /* find end of token and last non white space character */
			switch (*current) {
			case ' ':
			case '\t':
				/* space - don't update token_end */
				break;
			case ',':
			case '\0': /* end of string also marks the end of a token */
				array_insert_value(vals, token_start, token_end-token_start+1);
				state = 0;
				break;
			default:
				/* no white space, update token_end to include current character */
				token_end = current;
				break;
			}
			break;
		}
	}

	return 0;
}

static int request_uri_is_valid_char(unsigned char c) {
	return (c > 32 && c != 127 && c != 255);
}

__attribute_cold__
__attribute_noinline__
static int http_request_header_line_invalid(server *srv, int status, const char *msg) {
    if (srv->srvconf.log_request_header_on_error) {
        if (msg) log_error_write(srv, __FILE__, __LINE__, "s", msg);
    }
    return status;
}

__attribute_cold__
__attribute_noinline__
static int http_request_header_char_invalid(server *srv, char ch, const char *msg) {
    if (srv->srvconf.log_request_header_on_error) {
        if ((unsigned char)ch > 32 && ch != 127) {
            char buf[2] = { ch, '\0' };
            log_error_write(srv,__FILE__,__LINE__,"sSSS",msg,"('",buf,"')");
        }
        else {
            log_error_write(srv,__FILE__,__LINE__,"sSXS",msg,"(",ch,")");
        }
    }
    return 400;
}

enum keep_alive_set {
	HTTP_CONNECTION_UNSET,
	HTTP_CONNECTION_KEEPALIVE,
	HTTP_CONNECTION_CLOSE,
};

typedef struct {
	enum keep_alive_set keep_alive_set;
	char con_length_set;
	char *reqline_host;
	int reqline_hostlen;
	size_t reqline_len;
} parse_header_state;

static void init_parse_header_state(parse_header_state* state) {
	state->keep_alive_set = HTTP_CONNECTION_UNSET;
	state->con_length_set = 0;
	state->reqline_host = NULL;
	state->reqline_hostlen = 0;
	state->reqline_len = 0;
}

/* add header to list of headers
 * certain headers are also parsed
 * might drop a header if deemed unnecessary/broken
 *
 * returns 0 on success, HTTP status on error
 */
static int parse_single_header(server *srv, connection *con, parse_header_state *state, char *k, size_t klen, char *v, size_t vlen) {
    const enum http_header_e id = http_header_hkey_get(k, klen);
    buffer **saveb = NULL;

    /* strip leading whitespace */
    for (; vlen > 0 && (v[0] == ' ' || v[0] == '\t'); ++v, --vlen) ;

    /* strip trailing whitespace */
    while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t')) --vlen;

    /* empty header-fields are not allowed by HTTP-RFC, we just ignore them */
    if (0 == vlen) return 0; /* ignore header */

    /*
     * Note: k might not be '\0'-terminated
     */

    switch (id) {
      /*case HTTP_HEADER_OTHER:*/
      default:
        break;
      case HTTP_HEADER_HOST:
        if (!(con->request.htags & HTTP_HEADER_HOST)) {
            saveb = &con->request.http_host;
            if (vlen >= 1024) { /*(expecting < 256)*/
                return http_request_header_line_invalid(srv, 400, "uri-authority too long -> 400");
            }
        }
        else if (state->reqline_host) {
            /* ignore all Host: headers as we got Host in request line */
            return 0; /* ignore header */
        }
        else {
            return http_request_header_line_invalid(srv, 400, "duplicate Host header -> 400");
        }
        break;
      case HTTP_HEADER_CONNECTION:
        {
            array * const vals = srv->split_vals;
            array_reset_data_strings(vals);
            http_request_split_value(vals, v, vlen); /* split on , */
            for (size_t vi = 0; vi < vals->used; ++vi) {
                data_string *dsv = (data_string *)vals->data[vi];
                if (0 == buffer_caseless_compare(CONST_BUF_LEN(dsv->value),
                                                 CONST_STR_LEN("keep-alive"))) {
                    state->keep_alive_set = HTTP_CONNECTION_KEEPALIVE;
                    break;
                }
                else if (0 == buffer_caseless_compare(CONST_BUF_LEN(dsv->value),
                                                      CONST_STR_LEN("close"))) {
                    state->keep_alive_set = HTTP_CONNECTION_CLOSE;
                    break;
                }
            }
        }
        break;
      case HTTP_HEADER_CONTENT_TYPE:
        if (con->request.htags & HTTP_HEADER_CONTENT_TYPE) {
            return http_request_header_line_invalid(srv, 400, "duplicate Content-Type header -> 400");
        }
        break;
      case HTTP_HEADER_IF_NONE_MATCH:
        /* if dup, only the first one will survive */
        if (con->request.htags & HTTP_HEADER_IF_NONE_MATCH) {
            return 0; /* ignore header */
        }
        break;
      case HTTP_HEADER_CONTENT_LENGTH:
        if (!(con->request.htags & HTTP_HEADER_CONTENT_LENGTH)) {
            char *err;
            off_t r = strtoll(v, &err, 10);

            if (*err == '\0' && r >= 0) {
                con->request.content_length = r;
            }
            else {
                return http_request_header_line_invalid(srv, 400, "invalid Content-Length header -> 400");
            }
        }
        else {
            return http_request_header_line_invalid(srv, 400, "duplicate Content-Length header -> 400");
        }
        break;
      case HTTP_HEADER_IF_MODIFIED_SINCE:
        if (con->request.htags & HTTP_HEADER_IF_MODIFIED_SINCE) {
            /* Proxies sometimes send dup headers
             * if they are the same we ignore the second
             * if not, we raise an error */
            buffer *vb =
              http_header_request_get(con, HTTP_HEADER_IF_MODIFIED_SINCE,
                                      CONST_STR_LEN("If-Modified-Since"));
            if (vb && buffer_is_equal_caseless_string(vb, v, vlen)) {
                /* ignore it if they are the same */
                return 0; /* ignore header */
            }
            else {
                return http_request_header_line_invalid(srv, 400, "duplicate If-Modified-Since header -> 400");
            }
        }
        break;
    }

    con->request.htags |= id;
    http_header_request_append(con, id, k, klen, v, vlen);

    if (saveb) {
        *saveb = http_header_request_get(con, id, k, klen);
    }

    return 0;
}

static size_t http_request_parse_reqline(server *srv, connection *con, buffer *hdrs, parse_header_state *state) {
	char * const ptr = hdrs->ptr;
	char *uri = NULL, *proto = NULL;

	size_t i;
	const unsigned int http_header_strict = (con->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);

	/* hdrs must end with '\n' (already checked before parsing headers) */
      #ifdef __COVERITY__
	if (NULL == strchr(ptr, '\n')) return 400;
      #endif

	/*
	 * Request: "^(GET|POST|HEAD) ([^ ]+(\\?[^ ]+|)) (HTTP/1\\.[01])$"
	 * Option : "^([-a-zA-Z]+): (.+)$"
	 * End    : "^$"
	 */

	/* parse the first line of the request
	 *
	 * should be:
	 *
	 * <method> <uri> <protocol>\r\n
	 * */
	for (i = 0; ptr[i] != '\n'; ++i) {
		if (ptr[i] == ' ') {
			if (NULL == uri) uri = ptr + i + 1;
			else if (NULL == proto) proto = ptr + i + 1;
			else return http_request_header_line_invalid(srv, 400, "overlong request line; extra space -> 400"); /* ERROR, one space to much */
		}
	}
	ptr[i] = '\0';
	state->reqline_len = i+1;

			{
				char *nuri = NULL;
				size_t j, jlen;

				/* \r\n -> \0\0 */
			      #ifdef __COVERITY__
				if (0 == i) return 400;
			      #endif
				if (ptr[i-1] == '\r') {
					ptr[i-1] = '\0';
				} else if (http_header_strict) { /* '\n' */
					return http_request_header_line_invalid(srv, 400, "missing CR before LF in header -> 400");
				}

				if (NULL == proto) {
					return http_request_header_line_invalid(srv, 400, "incomplete request line -> 400");
				}

				con->request.http_method = get_http_method_key(ptr, uri - 1 - ptr);
				if (HTTP_METHOD_UNSET == con->request.http_method) {
					return http_request_header_line_invalid(srv, 501, "unknown http-method -> 501");
				}

				/*
				 * RFC7230:
				 *   HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
				 *   HTTP-name     = %x48.54.54.50 ; "HTTP", case-sensitive
				 */
				if (proto[0]=='H' && proto[1]=='T' && proto[2]=='T' && proto[3]=='P' && proto[4] == '/') {
					if (proto[5] == '1' && proto[6] == '.' && (proto[7] == '1' || proto[7] == '0')) {
						con->request.http_version = (proto[7] == '1') ? HTTP_VERSION_1_1 : HTTP_VERSION_1_0;
					} else {
						return http_request_header_line_invalid(srv, 505, "unknown HTTP version -> 505");
					}
				} else {
					return http_request_header_line_invalid(srv, 400, "unknown protocol -> 400");
				}

				jlen = (size_t)(proto - uri - 1);

				if (*uri == '/') {
					/* (common case) */
					buffer_copy_string_len(con->request.uri, uri, jlen);
				} else if (0 == buffer_caseless_compare(uri, 7, "http://", 7) &&
				    NULL != (nuri = memchr(uri + 7, '/', jlen-7))) {
					state->reqline_host = uri + 7;
					state->reqline_hostlen = nuri - state->reqline_host;

					buffer_copy_string_len(con->request.uri, nuri, proto - nuri - 1);
				} else if (0 == buffer_caseless_compare(uri, 8, "https://", 8) &&
				    NULL != (nuri = memchr(uri + 8, '/', jlen-8))) {
					state->reqline_host = uri + 8;
					state->reqline_hostlen = nuri - state->reqline_host;

					buffer_copy_string_len(con->request.uri, nuri, proto - nuri - 1);
				} else if (!http_header_strict
					   || (HTTP_METHOD_CONNECT == con->request.http_method && (uri[0] == ':' || light_isdigit(uri[0])))
					   || (HTTP_METHOD_OPTIONS == con->request.http_method && uri[0] == '*' && 1 == jlen)) {
					buffer_copy_string_len(con->request.uri, uri, jlen);
				} else {
					return http_request_header_line_invalid(srv, 400, "request-URI parse error -> 400");
				}

				/* check uri for invalid characters */
				jlen = buffer_string_length(con->request.uri);
				if (0 == jlen) return http_request_header_line_invalid(srv, 400, "no uri specified -> 400");
				if ((con->conf.http_parseopts & HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT)) {
					j = jlen; /* URI will be checked in http_response_prepare() */
				} else if (http_header_strict) {
					for (j = 0; j < jlen && request_uri_is_valid_char(con->request.uri->ptr[j]); j++) ;
				} else {
					char *z = memchr(con->request.uri->ptr, '\0', jlen);
					j = (NULL == z) ? jlen : (size_t)(z - con->request.uri->ptr);
				}
				if (j < jlen) {
					return http_request_header_char_invalid(srv, con->request.uri->ptr[j], "invalid character in URI -> 400");
				}

				buffer_copy_buffer(con->request.orig_uri, con->request.uri);
			}

	if (state->reqline_host) {
		/* Insert as host header */
		if (state->reqline_hostlen >= 1024) { /*(expecting < 256)*/
			return http_request_header_line_invalid(srv, 400, "uri-authority too long -> 400");
		}
		http_header_request_set(con, HTTP_HEADER_HOST, CONST_STR_LEN("Host"), state->reqline_host, state->reqline_hostlen);
		con->request.http_host = http_header_request_get(con, HTTP_HEADER_HOST, CONST_STR_LEN("Host"));
	}

	return 0;
}

int http_request_parse(server *srv, connection *con, buffer *hdrs) {
	char * const ptr = hdrs->ptr;
	char *value = NULL;
	size_t i, first, ilen;
	const unsigned int http_header_strict = (con->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);
	int status;

	parse_header_state state;
	init_parse_header_state(&state);

	status = http_request_parse_reqline(srv, con, hdrs, &state);
	if (0 != status) return status;

	i = first = state.reqline_len;

	if (ptr[i] == ' ' || ptr[i] == '\t') {
		return http_request_header_line_invalid(srv, 400, "WS at the start of first line -> 400");
	}

	ilen = buffer_string_length(hdrs);
	for (int is_key = 1, key_len = 0; i < ilen; ++i) {
		char *cur = ptr + i;

		if (is_key) {
			/**
			 * 1*<any CHAR except CTLs or separators>
			 * CTLs == 0-31 + 127, CHAR = 7-bit ascii (0..127)
			 *
			 */
			switch(*cur) {
			case ' ':
			case '\t':
				/* skip every thing up to the : */
				do { ++cur; } while (*cur == ' ' || *cur == '\t');
				if (*cur != ':') {
					return http_request_header_line_invalid(srv, 400, "WS character in key -> 400");
				}
				/* fall through */
			case ':':
				is_key = 0;
				key_len = i - first;
				value = cur + 1;
				i = cur - ptr;
				break;
			case '(':
			case ')':
			case '<':
			case '>':
			case '@':
			case ',':
			case ';':
			case '\\':
			case '\"':
			case '/':
			case '[':
			case ']':
			case '?':
			case '=':
			case '{':
			case '}':
				return http_request_header_char_invalid(srv, *cur, "invalid character in header key -> 400");
			case '\r':
				if (ptr[i+1] == '\n' && i == first) {
					/* End of Header */
					++i;
				} else {
					return http_request_header_line_invalid(srv, 400, "CR without LF -> 400");
				}
				break;
			case '\n':
				if (http_header_strict) {
					return http_request_header_line_invalid(srv, 400, "missing CR before LF in header -> 400");
				} else if (i == first) {
					/* End of Header */
					break;
				}
				/* fall through */
			default:
				if (http_header_strict ? (*cur < 32 || ((unsigned char)*cur) >= 127) : *cur == '\0') {
					return http_request_header_char_invalid(srv, *cur, "invalid character in header key -> 400");
				}
				/* ok */
				break;
			}
		} else {
			switch(*cur) {
			case '\r':
				if (cur[1] != '\n') {
					return http_request_header_line_invalid(srv, 400, "CR without LF -> 400");
				}
				if (cur[2] == ' ' || cur[2] == '\t') { /* header line folding */
					cur[0] = ' ';
					cur[1] = ' ';
					i += 2;
					continue;
				}
				++i;
				/* fall through */
			case '\n':
					if (*cur == '\n') {
						if (http_header_strict) {
							return http_request_header_line_invalid(srv, 400, "missing CR before LF in header -> 400");
						}
						if (cur[1] == ' ' || cur[1] == '\t') { /* header line folding */
							cur[0] = ' ';
							i += 1;
							continue;
						}
					}

					/* End of Headerline */
					*cur = '\0'; /*(for if value is further parsed and '\0' is expected at end of string)*/

					status = parse_single_header(srv, con, &state, ptr + first, key_len, value, cur - value);
					if (0 != status) return status;

					first = i+1;
					is_key = 1;
					value = NULL;
				break;
			case ' ':
			case '\t':
				break;
			default:
				if (http_header_strict ? (*cur >= 0 && *cur < 32) : *cur == '\0') {
					return http_request_header_char_invalid(srv, *cur, "invalid character in header -> 400");
				}
				break;
			}
		}
	}

	/* do some post-processing */

	if (con->request.http_version == HTTP_VERSION_1_1) {
		if (state.keep_alive_set != HTTP_CONNECTION_CLOSE) {
			/* no Connection-Header sent */

			/* HTTP/1.1 -> keep-alive default TRUE */
			con->keep_alive = 1;
		} else {
			con->keep_alive = 0;
		}

		/* RFC 2616, 14.23 */
		if (con->request.http_host == NULL ||
		    buffer_string_is_empty(con->request.http_host)) {
			return http_request_header_line_invalid(srv, 400, "HTTP/1.1 but Host missing -> 400");
		}
	} else {
		if (state.keep_alive_set == HTTP_CONNECTION_KEEPALIVE) {
			/* no Connection-Header sent */

			/* HTTP/1.0 -> keep-alive default FALSE  */
			con->keep_alive = 1;
		} else {
			con->keep_alive = 0;
		}
	}

	/* check hostname field if it is set */
	if (!buffer_is_empty(con->request.http_host) &&
	    0 != http_request_host_policy(con, con->request.http_host, con->proto)) {
		return http_request_header_line_invalid(srv, 400, "Invalid Hostname -> 400");
	}

        if (con->request.htags & HTTP_HEADER_TRANSFER_ENCODING) {
		buffer *vb = http_header_request_get(con, HTTP_HEADER_TRANSFER_ENCODING, CONST_STR_LEN("Transfer-Encoding"));
		if (NULL != vb) {
			if (con->request.http_version == HTTP_VERSION_1_0) {
				return http_request_header_line_invalid(srv, 400, "HTTP/1.0 with Transfer-Encoding (bad HTTP/1.0 proxy?) -> 400");
			}

			if (0 != buffer_caseless_compare(CONST_BUF_LEN(vb), CONST_STR_LEN("chunked"))) {
				/* Transfer-Encoding might contain additional encodings,
				 * which are not currently supported by lighttpd */
				return http_request_header_line_invalid(srv, 501, NULL); /* Not Implemented */
			}

			/* reset value for Transfer-Encoding, a hop-by-hop header,
			 * which must not be blindly forwarded to backends */
			http_header_request_unset(con, HTTP_HEADER_TRANSFER_ENCODING, CONST_STR_LEN("Transfer-Encoding"));

			/*(note: ignore whether or not Content-Length was provided)*/
		        if (con->request.htags & HTTP_HEADER_CONTENT_LENGTH) {
				http_header_request_unset(con, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
			}

			state.con_length_set = 1;
			con->request.content_length = -1;
		}
	}
        else if (con->request.htags & HTTP_HEADER_CONTENT_LENGTH) {
		state.con_length_set = 1;
	}

	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
		/* content-length is forbidden for those */
		if (state.con_length_set && 0 != con->request.content_length
		    && !(con->conf.http_parseopts & HTTP_PARSEOPT_METHOD_GET_BODY)) {
			return http_request_header_line_invalid(srv, 400, "GET/HEAD with content-length -> 400");
		}
		break;
	case HTTP_METHOD_POST:
		/* content-length is required for them */
		if (!state.con_length_set) {
			return http_request_header_line_invalid(srv, 411, "POST-request, but content-length missing -> 411");
		}
		break;
	default:
		break;
	}

	return 0;
}
