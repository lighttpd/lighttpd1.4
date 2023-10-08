#include "first.h"

#include "base.h"
#include "buffer.h"
#include "array.h"
#include "log.h"
#include "http_header.h"
#include "sock_addr.h"

#undef __declspec_dllimport__
#define __declspec_dllimport__  __declspec_dllexport__

#include "configfile.h"
#include "plugin.h"

#include <string.h>
#include <stdlib.h>     /* strtol */

__declspec_dllexport__
array plugin_stats; /* global */

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
    cfginfo->comp_key = dc->comp_key;
}

int config_capture(server *srv, int idx) {
    data_config * const dc = (data_config *)config_reference.data[idx];
    return (dc->capture_idx)
      ? dc->capture_idx
      : (dc->capture_idx = ++srv->config_captures);
}

int config_feature_bool (const server *srv, const char *feature, int default_value) {
    return srv->srvconf.feature_flags
      ? config_plugin_value_tobool(
          array_get_element_klen(srv->srvconf.feature_flags,
                                 feature, strlen(feature)), default_value)
      : default_value;
}

int32_t config_feature_int (const server *srv, const char *feature, int32_t default_value) {
    return srv->srvconf.feature_flags
      ? config_plugin_value_to_int32(
          array_get_element_klen(srv->srvconf.feature_flags,
                                 feature, strlen(feature)), default_value)
      : default_value;
}

int config_plugin_value_tobool (const data_unset *du, int default_value)
{
    if (NULL == du) return default_value;
    if (du->type == TYPE_STRING) {
        const buffer *b = &((const data_string *)du)->value;
        if (buffer_eq_icase_slen(b, CONST_STR_LEN("enable"))
            || buffer_eq_icase_slen(b, CONST_STR_LEN("enabled"))
            || buffer_eq_icase_slen(b, CONST_STR_LEN("true"))
            || buffer_eq_icase_slen(b, CONST_STR_LEN("1")))
            return 1;
        else if (buffer_eq_icase_slen(b, CONST_STR_LEN("disable"))
                 || buffer_eq_icase_slen(b, CONST_STR_LEN("disabled"))
                 || buffer_eq_icase_slen(b, CONST_STR_LEN("false"))
                 || buffer_eq_icase_slen(b, CONST_STR_LEN("0")))
            return 0;
        else
            return default_value;
    }
    else if (du->type == TYPE_INTEGER)
        return (0 != ((const data_integer *)du)->value);
    else
        return default_value;
}

int32_t config_plugin_value_to_int32 (const data_unset *du, int32_t default_value)
{
    if (NULL == du) return default_value;
    if (du->type == TYPE_STRING) {
        const buffer * const b = &((const data_string *)du)->value;
        char *err;
        long v = strtol(b->ptr, &err, 10);
        return (*err=='\0' && err != b->ptr && INT32_MIN <= v && v <= INT32_MAX)
          ? (int32_t)v
          : default_value;
    }
    else if (du->type == TYPE_INTEGER)
        return ((const data_integer *)du)->value;
    else
        return default_value;
}

int config_plugin_values_init_block(server * const srv, const array * const ca, const config_plugin_keys_t * const cpk, const char * const mname, config_plugin_value_t *cpv) {
    /*(cpv must be list with sufficient elements to store all matches + 1)*/

    int rc = 1; /* default is success */

    for (int i = 0; cpk[i].ktype != T_CONFIG_UNSET; ++i) {
        const data_unset * const du =
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
                  "got a string but expected a short integer: %s %s", cpk[i].k, v);
                rc = 0;
                continue;
              }
              case TYPE_INTEGER:
                cpv->v.shrt =
                  (unsigned short)((const data_integer *)du)->value;
                if (((const data_integer *)du)->value >= 0
                    && ((const data_integer *)du)->value <= 65535)
                    break;
                __attribute_fallthrough__
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
                        cpv->v.u = (unsigned int)l;
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
            {
                int v = config_plugin_value_tobool(du, -1);
                if (-1 == v) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "ERROR: unexpected type for key: %s (string) "
                      "\"(enable|disable)\"", cpk[i].k);
                    rc = 0;
                    continue;
                }
                cpv->v.u = v;
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
        const data_config * const dc =
          (const data_config *)srv->config_context->data[u];
        const array * const ca = dc->value;

        matches[n] = 0;
        for (int i = 0; cpk[i].ktype != T_CONFIG_UNSET; ++i) {
            const data_unset * const du =
              array_get_element_klen(ca, cpk[i].k, cpk[i].klen);
            if (NULL == du) continue; /* not found */

            ++matches[n];

            array_get_buf_ptr(touched, cpk[i].k, cpk[i].klen); /*(empty value)*/

            if (cpk[i].scope == T_CONFIG_SCOPE_CONNECTION || 0 == u) continue;

            if (cpk[i].scope == T_CONFIG_SCOPE_SERVER)
                /* server scope options should be set only in server scope */
                log_error(srv->errh, __FILE__, __LINE__,
                  "DEPRECATED: do not set server options in conditionals, "
                  "variable: %s", cpk[i].k);
            if (cpk[i].scope == T_CONFIG_SCOPE_SOCKET
                && (dc->comp!=COMP_SERVER_SOCKET || dc->cond!=CONFIG_COND_EQ))
                /* socket options should be set in socket or global scope */
                log_error(srv->errh, __FILE__, __LINE__,
                  "WARNING: %s must be in global scope or $SERVER[\"socket\"] "
                  "with '==', or else is ignored", cpk[i].k);
        }
        if (matches[n]) contexts[n++] = (unsigned short)u;
    }

    uint32_t elts = 0;
    for (uint32_t u = 0; u < n; ++u) elts += matches[u];
    p->nconfig = n;
    /*(+1 to include global scope, whether or not any directives exist)*/
    /*(+n for extra element to end each list)*/
    p->cvlist = (config_plugin_value_t *)
      ck_calloc(1+n+n+elts, sizeof(config_plugin_value_t));

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
    log_error(r->conf.errh, __FILE__, __LINE__, "%d (%s) result: %s (cond: %s)",
              dc->context_ndx, &"uncached"[cached ? 2 : 0], msg, dc->key.ptr);
}

static cond_result_t config_check_cond_nocache(request_st *r, const data_config *dc, int debug_cond, cond_cache_t *cache);

static cond_result_t config_check_cond_nocache_calc(request_st * const r, const data_config * const dc, const int debug_cond, cond_cache_t * const cache) {
    cache->result = config_check_cond_nocache(r, dc, debug_cond, cache);
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

static int config_pcre_match(request_st *r, const data_config *dc, const buffer *b);

static cond_result_t config_check_cond_nocache_eval(request_st * const r, const data_config * const dc, const int debug_cond, cond_cache_t * const cache);

static cond_result_t config_check_cond_nocache(request_st * const r, const data_config * const dc, const int debug_cond, cond_cache_t * const cache) {
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

	if (CONFIG_COND_ELSE == dc->cond)
		return (cache->local_result = COND_RESULT_TRUE);
		/* remember result of local condition for a partial reset */

	return config_check_cond_nocache_eval(r, dc, debug_cond, cache);
}

static cond_result_t config_check_cond_nocache_eval(request_st * const r, const data_config * const dc, const int debug_cond, cond_cache_t * const cache) {
	/* pass the rules */

	static const struct const_char_buffer {
	  const char *ptr;
	  uint32_t used;
	  uint32_t size;
	} empty_string = { "", 1, 0 };

	const buffer *l;
	switch (dc->comp) {
	case COMP_HTTP_HOST:
		l = &r->uri.authority;
		break;
	case COMP_HTTP_REMOTE_IP:
		l = r->dst_addr_buf;
		break;
	case COMP_HTTP_SCHEME:
		l = &r->uri.scheme;
		break;
	case COMP_HTTP_URL:
		l = &r->uri.path;
		break;
	case COMP_HTTP_QUERY_STRING:
		l = &r->uri.query;
		break;
	case COMP_SERVER_SOCKET:
		l = r->con->srv_socket->srv_token;
		break;
	case COMP_HTTP_REQUEST_HEADER:
		l = http_header_request_get(r, dc->ext, BUF_PTR_LEN(&dc->comp_tag));
		break;
	case COMP_HTTP_REQUEST_METHOD:
		l = http_method_buf(r->http_method);
		break;
	default:
		return (cache->local_result = COND_RESULT_FALSE);
	}

	if (__builtin_expect( (buffer_is_empty(l)), 0))
		l = (buffer *)&empty_string;

	if (debug_cond)
		log_error(r->conf.errh, __FILE__, __LINE__,
			"%s compare to %s", dc->comp_key, l->ptr);

	int match;
	switch(dc->cond) {
	case CONFIG_COND_NE:
	case CONFIG_COND_EQ:
		match = (dc->cond == CONFIG_COND_EQ);
		if (dc->comp == COMP_HTTP_HOST && dc->string.ptr[0] != '/') {
			uint_fast32_t llen = buffer_clen(l);
			uint_fast32_t dlen = buffer_clen(&dc->string);
			/* check names match, whether or not :port suffix present */
			/*(not strictly checking for port match for alt-svc flexibility,
			 * though if strings are same length, port is checked for match)*/
			/*(r->uri.authority not strictly checked here for excess ':')*/
			/*(r->uri.authority lowercased during request parsing)*/
			if (llen && llen != dlen) {
				match ^= ((llen > dlen)
				             ? l->ptr[dlen] == ':' && llen - dlen <= 6
				             : dc->string.ptr[(dlen = llen)] == ':')
				         && 0 == memcmp(l->ptr, dc->string.ptr, dlen);
				break;
			}
		}
		else if (dc->comp == COMP_HTTP_REMOTE_IP && dc->string.ptr[0] != '/') {
			/* CIDR mask comparisons only supported for COND_EQ, COND_NE */
			/* compare using structure data after end of string
			 * (generated at startup when parsing config) */
			const sock_addr * const addr = (sock_addr *)
			  (((uintptr_t)dc->string.ptr + dc->string.used + 1 + 7) & ~7);
			int bits = ((unsigned char *)dc->string.ptr)[dc->string.used];
			match ^= (bits)
			  ? sock_addr_is_addr_eq_bits(addr, r->dst_addr, bits)
			  : sock_addr_is_addr_eq(addr, r->dst_addr);
			break;
		}
		match ^= (buffer_is_equal(l, &dc->string));
		break;
	case CONFIG_COND_NOMATCH:
	case CONFIG_COND_MATCH:
		match = (dc->cond == CONFIG_COND_MATCH);
		match ^= (config_pcre_match(r, dc, l) > 0);
		break;
	case CONFIG_COND_PREFIX:
	case CONFIG_COND_SUFFIX:
		{
			uint_fast32_t llen = buffer_clen(l);
			uint_fast32_t dlen = buffer_clen(&dc->string);
			uint_fast32_t off  = (dc->cond == CONFIG_COND_PREFIX)
			                   ? 0
			                   : llen - dlen; /*(underflow caught below)*/
			match = !(dlen <= llen
			          && 0 == memcmp(l->ptr+off, dc->string.ptr, dlen));
		}
		break;
	default:
		match = 1; /* return (cache->local_result = COND_RESULT_FALSE); below */
		break;
	}
	/* remember result of local condition for a partial reset */
	cache->local_result = match ? COND_RESULT_FALSE : COND_RESULT_TRUE;
	return cache->local_result;
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

#ifdef HAVE_PCRE2_H
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#elif defined(HAVE_PCRE_H)
#include <pcre.h>
#endif

static int config_pcre_match(request_st * const r, const data_config * const dc, const buffer * const b) {

  #ifdef HAVE_PCRE2_H

    if (__builtin_expect( (0 == dc->capture_idx), 1))
        return pcre2_match(dc->code, (PCRE2_SPTR)BUF_PTR_LEN(b),
                           0, 0, dc->match_data, NULL);

    const int capture_offset = dc->capture_idx - 1;
    cond_match_t * const cond_match =
      r->cond_match[capture_offset] = r->cond_match_data + capture_offset;
    pcre2_match_data *match_data = cond_match->match_data;
    if (__builtin_expect( (NULL == match_data), 0)) {
        /*(allocate on demand)*/
      #if 0 /*(if we did not want to share dc->match_data across requests)*/
        /* index 0 is reused for all matches for which captures not used by
         * other directives within the condition, so allocate for up to 9
         * captures, plus 1 for %0 for full match.  Number of captures is
         * checked at startup to be <= 9 in data_config_pcre_compile()
         * (future: could save a few bytes if max captures were calculated
         *  at startup in config_finalize()) */
        match_data = cond_match->match_data = (0 == dc->capture_idx)
          ? pcre2_match_data_create(10, NULL)
          : pcre2_match_data_create_from_pattern(dc->code, NULL);
      #else
        match_data = cond_match->match_data =
          pcre2_match_data_create_from_pattern(dc->code, NULL);
      #endif
        force_assert(match_data);
        cond_match->matches = pcre2_get_ovector_pointer(match_data);
    }
    cond_match->comp_value = b; /*holds pointer to b (!) for pattern subst*/
    cond_match->captures =
      pcre2_match(dc->code, (PCRE2_SPTR)BUF_PTR_LEN(b), 0, 0, match_data, NULL);
    return cond_match->captures;

  #elif defined(HAVE_PCRE_H)

    if (__builtin_expect( (0 == dc->capture_idx), 1)) {
        int matches[3 * 10];
        return pcre_exec(dc->regex, dc->regex_study, BUF_PTR_LEN(b), 0, 0,
                         matches, sizeof(matches)/sizeof(*matches));
    }

    const int capture_offset = dc->capture_idx - 1;
    cond_match_t * const cond_match =
      r->cond_match[capture_offset] = r->cond_match_data + capture_offset;
    if (__builtin_expect( (NULL == cond_match->matches), 0)) {
        /*(allocate on demand)*/
        cond_match->matches = ck_malloc(dc->ovec_nelts * sizeof(int));
    }
    cond_match->comp_value = b; /*holds pointer to b (!) for pattern subst*/
    cond_match->captures =
      pcre_exec(dc->regex, dc->regex_study, BUF_PTR_LEN(b), 0, 0,
                cond_match->matches, dc->ovec_nelts);
    return cond_match->captures;

  #else

    UNUSED(r);
    UNUSED(dc);
    UNUSED(b);
    return 0;

  #endif
}
