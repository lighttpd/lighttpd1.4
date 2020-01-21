#include "first.h"

#include "base.h"
#include "buffer.h"
#include "array.h"
#include "log.h"
#include "http_header.h"
#include "sock_addr.h"

#include "configfile.h"
#include "plugin.h"

#include <string.h>
#include <stdlib.h>     /* strtol */

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

/* internal reference to srv->config_context array of (data_config *) */
static struct {
    const data_config * const *data; /* (srv->config_context->data) */
    uint32_t used;                   /* (srv->config_context->used) */
} config_reference;


void config_get_config_cond_info(config_cond_info * const cfginfo, uint32_t idx) {
    const data_config * const dc = (data_config *)config_reference.data[idx];
    cfginfo->comp = dc->comp;
    cfginfo->cond = dc->cond;
    cfginfo->string = &dc->string;
    cfginfo->comp_tag = dc->comp_tag;
    cfginfo->comp_key = dc->comp_key;
    cfginfo->op = dc->op;
}

int config_plugin_values_init_block(server * const srv, const array * const ca, const config_plugin_keys_t * const cpk, const char * const mname, config_plugin_value_t *cpv) {
    /*(cpv must be list with sufficient elements to store all matches + 1)*/

    int rc = 1; /* default is success */

    for (int i = 0; cpk[i].ktype != T_CONFIG_UNSET; ++i) {
        data_unset * const du =
          array_get_element_klen(ca, cpk[i].k, cpk[i].klen);
        if (NULL == du) continue; /* not found */

        cpv->k_id = i;
        cpv->vtype = cpk[i].ktype;

        switch (cpk[i].ktype) {
          case T_CONFIG_ARRAY:
          case T_CONFIG_ARRAY_KVANY:
          case T_CONFIG_ARRAY_KVARRAY:
          case T_CONFIG_ARRAY_KVSTRING:
          case T_CONFIG_ARRAY_VLIST:
            if (du->type == TYPE_ARRAY) {
                cpv->v.a = &((const data_array *)du)->value;
            }
            else {
                log_error(srv->errh, __FILE__, __LINE__,
                  "%s should have been a list like "
                  "%s = ( \"...\" )", cpk[i].k, cpk[i].k);
                rc = 0;
                continue;
            }
            switch (cpk[i].ktype) {
              case T_CONFIG_ARRAY_KVANY:
                if (!array_is_kvany(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s should have been a list of key => values like "
                      "%s = ( \"...\" => \"...\", \"...\" => \"...\" )",
                    cpk[i].k, cpk[i].k);
                    rc = 0;
                    continue;
                }
                break;
              case T_CONFIG_ARRAY_KVARRAY:
                if (!array_is_kvarray(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s should have been a list of key => list like "
                      "%s = ( \"...\" => ( \"...\" => \"...\" ) )",
                    cpk[i].k, cpk[i].k);
                    rc = 0;
                    continue;
                }
                break;
              case T_CONFIG_ARRAY_KVSTRING:
                if (!array_is_kvstring(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s should have been a list of key => string values like "
                      "%s = ( \"...\" => \"...\", \"...\" => \"...\" )",
                    cpk[i].k, cpk[i].k);
                    rc = 0;
                    continue;
                }
                break;
              case T_CONFIG_ARRAY_VLIST:
                if (!array_is_vlist(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s should have been a list of string values like "
                      "%s = ( \"...\", \"...\" )",
                    cpk[i].k, cpk[i].k);
                    rc = 0;
                    continue;
                }
                break;
              /*case T_CONFIG_ARRAY:*/
              default:
                break;
            }
            break;
          case T_CONFIG_STRING:
            if (du->type == TYPE_STRING) {
                cpv->v.b = &((const data_string *)du)->value;
            }
            else {
                log_error(srv->errh, __FILE__, __LINE__,
                  "%s should have been a string like ... = \"...\"", cpk[i].k);
                rc = 0;
                continue;
            }
            break;
          case T_CONFIG_SHORT:
            switch(du->type) {
              case TYPE_INTEGER:
                cpv->v.shrt =
                  (unsigned short)((const data_integer *)du)->value;
                break;
              case TYPE_STRING: {
                /* If the value came from an environment variable, then it is
                 * a data_string, although it may contain a number in ASCII
                 * decimal format.  We try to interpret the string as a decimal
                 * short before giving up, in order to support setting numeric
                 * values with environment variables (e.g. port number).
                 */
                const char * const v = ((const data_string *)du)->value.ptr;
                if (v && *v) {
                    char *e;
                    long l = strtol(v, &e, 10);
                    if (e != v && !*e && l >= 0 && l <= 65535) {
                        cpv->v.shrt = (unsigned short)l;
                        break;
                    }
                }
                log_error(srv->errh, __FILE__, __LINE__,
                  "got a string but expected a short: %s %s", cpk[i].k, v);
                rc = 0;
                continue;
              }
              default:
                log_error(srv->errh, __FILE__, __LINE__,
                  "unexpected type for key: %s %d expected a short integer, "
                  "range 0 ... 65535", cpk[i].k, du->type);
                rc = 0;
                continue;
            }
            break;
          case T_CONFIG_INT:
            switch(du->type) {
              case TYPE_INTEGER:
                cpv->v.u = ((const data_integer *)du)->value;
                break;
              case TYPE_STRING: {
                const char * const v = ((const data_string *)du)->value.ptr;
                if (v && *v) {
                    char *e;
                    long l = strtol(v, &e, 10);
                    if (e != v && !*e && l >= 0) {
                        cpv->v.shrt = (unsigned int)l;
                        break;
                    }
                }
                log_error(srv->errh, __FILE__, __LINE__,
                  "got a string but expected an integer: %s %s",cpk[i].k,v);
                rc = 0;
                continue;
              }
              default:
                log_error(srv->errh, __FILE__, __LINE__,
                  "unexpected type for key: %s %d expected an integer, "
                  "range 0 ... 4294967295", cpk[i].k, du->type);
                rc = 0;
                continue;
            }
            break;
          case T_CONFIG_BOOL:
            if (du->type == TYPE_STRING) {
                const buffer *b = &((const data_string *)du)->value;
                if (buffer_eq_icase_slen(b, CONST_STR_LEN("enable"))
                    || buffer_eq_icase_slen(b, CONST_STR_LEN("true"))) {
                    cpv->v.u = 1;
                }
                else if (buffer_eq_icase_slen(b, CONST_STR_LEN("disable"))
                         || buffer_eq_icase_slen(b,CONST_STR_LEN("false"))) {
                    cpv->v.u = 0;
                }
                else {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "ERROR: unexpected value for key: %s %s (enable|disable)",
                      cpk[i].k, b->ptr);
                    rc = 0;
                    continue;
                }
            }
            else if (du->type == TYPE_INTEGER) {
                cpv->v.u = (0 != ((const data_integer *)du)->value);
            }
            else {
                log_error(srv->errh, __FILE__, __LINE__,
                  "ERROR: unexpected type for key: %s (string) "
                  "\"(enable|disable)\"", cpk[i].k);
                rc = 0;
                continue;
            }
            break;
          case T_CONFIG_LOCAL:
          case T_CONFIG_UNSET:
            continue;
          case T_CONFIG_UNSUPPORTED:
            log_error(srv->errh, __FILE__, __LINE__,
              "ERROR: found unsupported key: %s (%s)", cpk[i].k, mname);
            srv->srvconf.config_unsupported = 1;
            continue;
          case T_CONFIG_DEPRECATED:
            log_error(srv->errh, __FILE__, __LINE__,
              "ERROR: found deprecated key: %s (%s)", cpk[i].k, mname);
            srv->srvconf.config_deprecated = 1;
            continue;
        }

        ++cpv;
    }

    cpv->k_id = -1; /* indicate list end */

    return rc;
}

int config_plugin_values_init(server * const srv, void *p_d, const config_plugin_keys_t * const cpk, const char * const mname) {
    plugin_data_base * const p = (plugin_data_base *)p_d;
    array * const touched = srv->srvconf.config_touched;
    unsigned char matches[4096];   /*directives matches (4k is way too many!)*/
    unsigned short contexts[4096]; /*conditions matches (4k is way too many!)*/
    uint32_t n = 0;
    int rc = 1; /* default is success */
    force_assert(sizeof(matches) >= srv->config_context->used);

    /* save config reference data for later internal use
     * (config_plugin_values_init() is called with same srv->config_context) */
    config_reference.data = (const data_config * const *)srv->config_context->data;
    config_reference.used = srv->config_context->used;

    /* traverse config contexts twice: once to count, once to store matches */

    for (uint32_t u = 0; u < srv->config_context->used; ++u) {
        const array *ca =
          ((data_config const *)srv->config_context->data[u])->value;

        matches[n] = 0;
        for (int i = 0; cpk[i].ktype != T_CONFIG_UNSET; ++i) {
            data_unset * const du =
              array_get_element_klen(ca, cpk[i].k, cpk[i].klen);
            if (NULL == du) continue; /* not found */

            ++matches[n];

            array_set_key_value(touched,cpk[i].k,cpk[i].klen,CONST_STR_LEN(""));

            if (cpk[i].scope == T_CONFIG_SCOPE_SERVER && 0 != u) {
                /* server scope options should be set only in server scope */
                log_error(srv->errh, __FILE__, __LINE__,
                  "DEPRECATED: do not set server options in conditionals, "
                  "variable: %s", cpk[i].k);
            }
        }
        if (matches[n]) contexts[n++] = (unsigned short)u;
    }

    uint32_t elts = 0;
    for (uint32_t u = 0; u < n; ++u) elts += matches[u];
    p->nconfig = n;
    /*(+1 to include global scope, whether or not any directives exist)*/
    /*(+n for extra element to end each list)*/
    p->cvlist = (config_plugin_value_t *)
      calloc(1+n+n+elts, sizeof(config_plugin_value_t));
    force_assert(p->cvlist);

    elts = 1+n;
    /* shift past first element if no directives in global scope */
    const uint32_t shft = (0 != n && 0 != contexts[0]);
    if (shft) ++p->nconfig;
    for (uint32_t u = 0; u < n; ++u) {
        config_plugin_value_t * const cpv = p->cvlist+shft+u;
        cpv->k_id = (int)contexts[u];
        cpv->v.u2[0] = elts;
        cpv->v.u2[1] = matches[u];
        elts += matches[u]+1;     /* +1 to end list with cpv->k_id = -1 */
    }

    for (uint32_t u = 0; u < n; ++u) {
        const array *ca =
          ((data_config const *)srv->config_context->data[contexts[u]])->value;
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[shft+u].v.u2[0];
        if (!config_plugin_values_init_block(srv, ca, cpk, mname, cpv))
            rc = 0;
    }

    return rc;
}

__attribute_cold__
__attribute_noinline__
static void config_cond_result_trace(request_st * const r, const data_config * const dc, const int cached) {
    cond_cache_t * const cache = &r->cond_cache[dc->context_ndx];
    const char *msg;
    switch (cache->result) {
      case COND_RESULT_UNSET: msg = "unset"; break;
      case COND_RESULT_SKIP:  msg = "skipped"; break;
      case COND_RESULT_FALSE: msg = "false"; break;
      case COND_RESULT_TRUE:  msg = "true"; break;
      default:                msg = "invalid cond_result_t"; break;
    }
    log_error(r->conf.errh, __FILE__, __LINE__, "%d (%s) result: %s",
              dc->context_ndx, &"uncached"[cached ? 2 : 0], msg);
}

static cond_result_t config_check_cond_nocache(request_st *r, const data_config *dc, int debug_cond, cond_cache_t *cache);

static cond_result_t config_check_cond_nocache_calc(request_st * const r, const data_config * const dc, const int debug_cond, cond_cache_t * const cache) {
    cache->result = config_check_cond_nocache(r, dc, debug_cond, cache);
    switch (cache->result) {
      case COND_RESULT_FALSE:
      case COND_RESULT_TRUE:
        /* remember result of local condition for a partial reset */
        cache->local_result = cache->result;
        break;
      default:
        break;
    }
    if (debug_cond) config_cond_result_trace(r, dc, 0);
    return cache->result;
}

static cond_result_t config_check_cond_cached(request_st * const r, const data_config * const dc, const int debug_cond) {
    cond_cache_t * const cache = &r->cond_cache[dc->context_ndx];
    if (COND_RESULT_UNSET != cache->result) {
        if (debug_cond) config_cond_result_trace(r, dc, 1);
        return cache->result;
    }
    return config_check_cond_nocache_calc(r, dc, debug_cond, cache);
}

static int config_addrstr_eq_remote_ip_mask(request_st * const r, const char * const addrstr, const int nm_bits, sock_addr * const rmt) {
	/* special-case 0 == nm_bits to mean "all bits of the address" in addrstr */
	sock_addr addr;
	if (1 == sock_addr_inet_pton(&addr, addrstr, AF_INET, 0)) {
		if (nm_bits > 32) {
			log_error(r->conf.errh, __FILE__, __LINE__, "ERROR: ipv4 netmask too large: %d", nm_bits);
			return -1;
		}
	} else if (1 == sock_addr_inet_pton(&addr, addrstr, AF_INET6, 0)) {
		if (nm_bits > 128) {
			log_error(r->conf.errh, __FILE__, __LINE__, "ERROR: ipv6 netmask too large: %d", nm_bits);
			return -1;
		}
	} else {
		log_error(r->conf.errh, __FILE__, __LINE__, "ERROR: ip addr is invalid: %s", addrstr);
		return -1;
	}
	return sock_addr_is_addr_eq_bits(&addr, rmt, nm_bits);
}

static int config_addrbuf_eq_remote_ip_mask(request_st * const r, const buffer * const string, char * const nm_slash, sock_addr * const rmt) {
	char *err;
	int nm_bits = strtol(nm_slash + 1, &err, 10);
	size_t addrstrlen = (size_t)(nm_slash - string->ptr);
	char addrstr[64]; /*(larger than INET_ADDRSTRLEN and INET6_ADDRSTRLEN)*/

	if (*err) {
		log_error(r->conf.errh, __FILE__, __LINE__, "ERROR: non-digit found in netmask: %s %s", string->ptr, err);
		return -1;
	}

	if (nm_bits <= 0) {
		if (*(nm_slash+1) == '\0') {
			log_error(r->conf.errh, __FILE__, __LINE__, "ERROR: no number after / %s", string->ptr);
		} else {
			log_error(r->conf.errh, __FILE__, __LINE__, "ERROR: invalid netmask <= 0: %s %s", string->ptr, err);
		}
		return -1;
	}

	if (addrstrlen >= sizeof(addrstr)) {
		log_error(r->conf.errh, __FILE__, __LINE__, "ERROR: address string too long: %s", string->ptr);
		return -1;
	}

	memcpy(addrstr, string->ptr, addrstrlen);
	addrstr[addrstrlen] = '\0';

	return config_addrstr_eq_remote_ip_mask(r, addrstr, nm_bits, rmt);
}

static int data_config_pcre_exec(const data_config *dc, cond_cache_t *cache, const buffer *b, cond_match_t *cond_match);

static cond_result_t config_check_cond_nocache(request_st * const r, const data_config * const dc, const int debug_cond, cond_cache_t * const cache) {
	static struct const_char_buffer {
	  const char *ptr;
	  uint32_t used;
	  uint32_t size;
	} empty_string = { "", 1, 0 };

	/* check parent first */
	if (dc->parent && dc->parent->context_ndx) {
		/**
		 * a nested conditional 
		 *
		 * if the parent is not decided yet or false, we can't be true either 
		 */
		if (debug_cond) {
			log_error(r->conf.errh, __FILE__, __LINE__, "go parent %s", dc->parent->key.ptr);
		}

		switch (config_check_cond_cached(r, dc->parent, debug_cond)) {
		case COND_RESULT_UNSET:
			/* decide later */
			return COND_RESULT_UNSET;
		case COND_RESULT_SKIP:
		case COND_RESULT_FALSE:
			/* failed precondition */
			return COND_RESULT_SKIP;
		case COND_RESULT_TRUE:
			/* proceed */
			break;
		}
	}

	if (dc->prev) {
		/**
		 * a else branch; can only be executed if the previous branch
		 * was evaluated as "false" (not unset/skipped/true)
		 */
		if (debug_cond) {
			log_error(r->conf.errh, __FILE__, __LINE__, "go prev %s", dc->prev->key.ptr);
		}

		/* make sure prev is checked first */
		switch (config_check_cond_cached(r, dc->prev, debug_cond)) {
		case COND_RESULT_UNSET:
			/* decide later */
			return COND_RESULT_UNSET;
		case COND_RESULT_SKIP:
		case COND_RESULT_TRUE:
			/* failed precondition */
			return COND_RESULT_SKIP;
		case COND_RESULT_FALSE:
			/* proceed */
			break;
		}
	}

	if (!(r->conditional_is_valid & (1 << dc->comp))) {
		if (debug_cond) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "%d %s not available yet", dc->comp, dc->key.ptr);
		}

		return COND_RESULT_UNSET;
	}

	/* if we had a real result before and weren't cleared just return it */
	switch (cache->local_result) {
	case COND_RESULT_TRUE:
	case COND_RESULT_FALSE:
		return cache->local_result;
	default:
		break;
	}

	if (CONFIG_COND_ELSE == dc->cond) return COND_RESULT_TRUE;

	/* pass the rules */

	buffer *l;
	switch (dc->comp) {
	case COMP_HTTP_HOST:

		l = &r->uri.authority;

		if (buffer_string_is_empty(l)) {
			l = (buffer *)&empty_string;
			break;
		}

		switch(dc->cond) {
		case CONFIG_COND_NE:
		case CONFIG_COND_EQ: {
			unsigned short port = sock_addr_get_port(&r->con->srv_socket->addr);
			if (0 == port) break;
			const char *ck_colon = strchr(dc->string.ptr, ':');
			const char *val_colon = strchr(l->ptr, ':');

			/* append server-port if necessary */
			if (NULL != ck_colon && NULL == val_colon) {
				/* condition "host:port" but client send "host" */
				buffer *tb = r->tmp_buf;
				buffer_copy_buffer(tb, l);
				buffer_append_string_len(tb, CONST_STR_LEN(":"));
				buffer_append_int(tb, port);
				l = tb;
			} else if (NULL != val_colon && NULL == ck_colon) {
				/* condition "host" but client send "host:port" */
				buffer *tb = r->tmp_buf;
				buffer_copy_string_len(tb, l->ptr, val_colon - l->ptr);
				l = tb;
			}
			break;
		}
		default:
			break;
		}

		break;
	case COMP_HTTP_REMOTE_IP: {
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
		    (NULL != (nm_slash = strchr(dc->string.ptr, '/')))) {
			switch (config_addrbuf_eq_remote_ip_mask(r, &dc->string, nm_slash, &r->con->dst_addr)) {
			case  1: return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
			case  0: return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
			case -1: return COND_RESULT_FALSE; /*(error parsing configfile entry)*/
			}
		}
		l = r->con->dst_addr_buf;
		break;
	}
	case COMP_HTTP_SCHEME:
		l = &r->uri.scheme;
		break;

	case COMP_HTTP_URL:
		l = &r->uri.path;
		break;

	case COMP_HTTP_QUERY_STRING:
		l = &r->uri.query;
		if (NULL == l->ptr) l = (buffer *)&empty_string;
		break;

	case COMP_SERVER_SOCKET:
		l = r->con->srv_socket->srv_token;
		break;

	case COMP_HTTP_REQUEST_HEADER:
		*((const buffer **)&l) = http_header_request_get(r, HTTP_HEADER_UNSPECIFIED, CONST_BUF_LEN(dc->comp_tag));
		if (NULL == l) l = (buffer *)&empty_string;
		break;
	case COMP_HTTP_REQUEST_METHOD:
		l = r->tmp_buf;
		buffer_clear(l);
		http_method_append(l, r->http_method);
		break;
	default:
		return COND_RESULT_FALSE;
	}

	if (NULL == l) { /*(should not happen)*/
		log_error(r->conf.errh, __FILE__, __LINE__,
			"%s () compare to NULL", dc->comp_key->ptr);
		return COND_RESULT_FALSE;
	}
	else if (debug_cond) {
		log_error(r->conf.errh, __FILE__, __LINE__,
			"%s (%s) compare to %s", dc->comp_key->ptr, l->ptr, dc->string.ptr);
	}

	switch(dc->cond) {
	case CONFIG_COND_NE:
	case CONFIG_COND_EQ:
		if (buffer_is_equal(l, &dc->string)) {
			return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
		} else {
			return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
		}
	case CONFIG_COND_NOMATCH:
	case CONFIG_COND_MATCH: {
		cond_match_t *cond_match = r->cond_match + dc->context_ndx;
		if (data_config_pcre_exec(dc, cache, l, cond_match) > 0) {
			return (dc->cond == CONFIG_COND_MATCH) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
		} else {
			/* cache is already cleared */
			return (dc->cond == CONFIG_COND_MATCH) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
		}
	}
	default:
		/* no way */
		break;
	}

	return COND_RESULT_FALSE;
}

__attribute_noinline__
static cond_result_t config_check_cond_calc(request_st * const r, const int context_ndx, cond_cache_t * const cache) {
    const data_config * const dc = config_reference.data[context_ndx];
    const int debug_cond = r->conf.log_condition_handling;
    if (debug_cond) {
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "=== start of condition block ===");
    }
    return config_check_cond_nocache_calc(r, dc, debug_cond, cache);
}

/* future: might make static inline in header for plugins */
int config_check_cond(request_st * const r, const int context_ndx) {
    cond_cache_t * const cache = &r->cond_cache[context_ndx];
    return COND_RESULT_TRUE
        == (COND_RESULT_UNSET != cache->result
              ? (cond_result_t)cache->result
              : config_check_cond_calc(r, context_ndx, cache));
}

/* if we reset the cache result for a node, we also need to clear all
 * child nodes and else-branches*/
static void config_cond_clear_node(cond_cache_t * const cond_cache, const data_config * const dc) {
	/* if a node is "unset" all children are unset too */
	if (cond_cache[dc->context_ndx].result != COND_RESULT_UNSET) {
		cond_cache[dc->context_ndx].result = COND_RESULT_UNSET;

		for (uint32_t i = 0; i < dc->children.used; ++i) {
			const data_config *dc_child = dc->children.data[i];
			if (NULL == dc_child->prev) {
				/* only call for first node in if-else chain */
				config_cond_clear_node(cond_cache, dc_child);
			}
		}
		if (NULL != dc->next) config_cond_clear_node(cond_cache, dc->next);
	}
}

/**
 * reset the config-cache for a named item
 *
 * if the item is COND_LAST_ELEMENT we reset all items
 */
void config_cond_cache_reset_item(request_st * const r, comp_key_t item) {
	cond_cache_t * const cond_cache = r->cond_cache;
	const data_config * const * const data = config_reference.data;
	const uint32_t used = config_reference.used;
	for (uint32_t i = 0; i < used; ++i) {
		const data_config * const dc = data[i];

		if (item == dc->comp) {
			/* clear local_result */
			cond_cache[i].local_result = COND_RESULT_UNSET;
			/* clear result in subtree (including the node itself) */
			config_cond_clear_node(cond_cache, dc);
		}
	}
}

/**
 * reset the config cache to its initial state at connection start
 */
void config_cond_cache_reset(request_st * const r) {
	/* resetting all entries; no need to follow children as in config_cond_cache_reset_item */
	/* static_assert(0 == COND_RESULT_UNSET); */
	const uint32_t used = config_reference.used;
	if (used > 1)
		memset(r->cond_cache, 0, used*sizeof(cond_cache_t));
}

#ifdef HAVE_PCRE_H
#include <pcre.h>
#endif

static int data_config_pcre_exec(const data_config *dc, cond_cache_t *cache, const buffer *b, cond_match_t *cond_match) {
#ifdef HAVE_PCRE_H
    #ifndef elementsof
    #define elementsof(x) (sizeof(x) / sizeof(x[0]))
    #endif
    cache->patterncount =
      pcre_exec(dc->regex, dc->regex_study, CONST_BUF_LEN(b), 0, 0,
                cond_match->matches, elementsof(cond_match->matches));
    if (cache->patterncount > 0)
        cond_match->comp_value = b; /*holds pointer to b (!) for pattern subst*/
    return cache->patterncount;
#else
    UNUSED(dc);
    UNUSED(cache);
    UNUSED(b);
    UNUSED(cond_match);
    return 0;
#endif
}
