#include "first.h"

#include "fdevent.h"
#include "fdlog.h"
#include "log.h"
#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "http_cgi.h"
#include "http_chunk.h"
#include "http_etag.h"
#include "http_header.h"
#include "http_status.h"
#include "request.h"
#include "stat_cache.h"

#include "plugin.h"

#include "response.h"

#include "sys-socket.h"
#include "sys-time.h"
#include "sys-unistd.h" /* <unistd.h> */

#include <sys/types.h>
#include <sys/stat.h>
#include "sys-wait.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef HAVE_PWD_H
# include <pwd.h>
#endif

typedef struct {
	const array *ssi_extension;
	const buffer *content_type;
	unsigned short conditional_requests;
	unsigned short ssi_exec;
	unsigned short ssi_recursion_max;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config defaults;
	array *ssi_vars;
	array *ssi_cgi_env;
	buffer stat_fn;
	buffer timefmt;
} plugin_data;

typedef struct {
	array *ssi_vars;
	array *ssi_cgi_env;
	buffer *stat_fn;
	buffer *timefmt;
	int sizefmt;

	int if_level, if_is_false_level, if_is_false, if_is_false_endif;
	unsigned short ssi_recursion_depth;

	chunkqueue wq;
	log_error_st *errh;
	plugin_config conf;
} handler_ctx;

__attribute_returns_nonnull__
static handler_ctx * handler_ctx_init (plugin_config * const pconf, plugin_data * const p, log_error_st *errh) {
	handler_ctx *hctx = ck_calloc(1, sizeof(*hctx));
	hctx->errh = errh;
	hctx->timefmt = &p->timefmt;        /* thread-safety todo */
	hctx->stat_fn = &p->stat_fn;        /* thread-safety todo */
	hctx->ssi_vars = p->ssi_vars;       /* thread-safety todo */
	hctx->ssi_cgi_env = p->ssi_cgi_env; /* thread-safety todo */
	memcpy(&hctx->conf, pconf, sizeof(plugin_config));
	chunkqueue_init(&hctx->wq);
	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	chunkqueue_reset(&hctx->wq);
	free(hctx);
}

/* The newest modified time of included files for include statement */
static volatile unix_time64_t include_file_last_mtime = 0;

INIT_FUNC(mod_ssi_init) {
	plugin_data * const p = ck_calloc(1, sizeof(*p));
	p->ssi_vars = array_init(8);
	p->ssi_cgi_env = array_init(32);
	return p;
}

FREE_FUNC(mod_ssi_free) {
	plugin_data *p = p_d;
	array_free(p->ssi_vars);
	array_free(p->ssi_cgi_env);
	free(p->timefmt.ptr);
	free(p->stat_fn.ptr);
}

static void mod_ssi_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* ssi.extension */
        pconf->ssi_extension = cpv->v.a;
        break;
      case 1: /* ssi.content-type */
        pconf->content_type = cpv->v.b;
        break;
      case 2: /* ssi.conditional-requests */
        pconf->conditional_requests = cpv->v.u;
        break;
      case 3: /* ssi.exec */
        pconf->ssi_exec = cpv->v.u;
        break;
      case 4: /* ssi.recursion-max */
        pconf->ssi_recursion_max = cpv->v.shrt;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_ssi_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_ssi_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_ssi_patch_config(request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_ssi_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_ssi_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssi.extension"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssi.content-type"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssi.conditional-requests"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssi.exec"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssi.recursion-max"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_ssi"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* ssi.extension */
                break;
              case 1: /* ssi.content-type */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 2: /* ssi.conditional-requests */
              case 3: /* ssi.exec */
              case 4: /* ssi.recursion-max */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.ssi_exec = 1;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_ssi_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}




#define TK_AND                             1
#define TK_OR                              2
#define TK_EQ                              3
#define TK_NE                              4
#define TK_GT                              5
#define TK_GE                              6
#define TK_LT                              7
#define TK_LE                              8
#define TK_NOT                             9
#define TK_LPARAN                         10
#define TK_RPARAN                         11
#define TK_VALUE                          12

typedef struct {
    const char *input;
    size_t offset;
    size_t size;
    int in_brace;
    int depth;
    handler_ctx *p;
} ssi_tokenizer_t;

typedef struct {
    buffer  str;
    enum { SSI_TYPE_UNSET, SSI_TYPE_BOOL, SSI_TYPE_STRING } type;
    int     bo;
} ssi_val_t;

__attribute_pure__
static int ssi_val_to_bool(const ssi_val_t *B) {
    return B->type == SSI_TYPE_BOOL ? B->bo : !buffer_is_blank(&B->str);
}

__attribute_pure__
static int ssi_eval_expr_cmp(const ssi_val_t * const v1, const ssi_val_t * const v2, const int cond) {
    int cmp = (v1->type != SSI_TYPE_BOOL && v2->type != SSI_TYPE_BOOL)
      ? strcmp(v1->str.ptr ? v1->str.ptr : "",
               v2->str.ptr ? v2->str.ptr : "")
      : ssi_val_to_bool(v1) - ssi_val_to_bool(v2);
    switch (cond) {
      case TK_EQ: return (cmp == 0);
      case TK_NE: return (cmp != 0);
      case TK_GE: return (cmp >= 0);
      case TK_GT: return (cmp >  0);
      case TK_LE: return (cmp <= 0);
      case TK_LT: return (cmp <  0);
      default:    return 0;/*(should not happen)*/
    }
}

__attribute_pure__
static int ssi_eval_expr_cmp_bool(const ssi_val_t * const v1, const ssi_val_t * const v2, const int cond) {
    return (cond == TK_OR)
      ? ssi_val_to_bool(v1) || ssi_val_to_bool(v2)  /* TK_OR */
      : ssi_val_to_bool(v1) && ssi_val_to_bool(v2); /* TK_AND */
}

static void ssi_eval_expr_append_val(buffer * const b, const char *s, const size_t slen) {
    if (buffer_is_blank(b))
        buffer_append_string_len(b, s, slen);
    else if (slen)
        buffer_append_str2(b, CONST_STR_LEN(" "), s, slen);
}

static int ssi_expr_tokenizer(ssi_tokenizer_t * const t, buffer * const token) {
    size_t i;

    while (t->offset < t->size
           && (t->input[t->offset] == ' ' || t->input[t->offset] == '\t')) {
        ++t->offset;
    }
    if (t->offset >= t->size)
        return 0;
    if (t->input[t->offset] == '\0') {
        log_error(t->p->errh, __FILE__, __LINE__,
          "pos: %zu foobar", t->offset+1);
        return -1;
    }

    switch (t->input[t->offset]) {
      case '=':
       #if 0 /*(maybe accept "==", too)*/
        if (t->input[t->offset + 1] == '=')
            ++t->offset;
       #endif
        t->offset++;
        return TK_EQ;
      case '>':
        if (t->input[t->offset + 1] == '=') {
            t->offset += 2;
            return TK_GE;
        }
        else {
            t->offset += 1;
            return TK_GT;
        }
      case '<':
        if (t->input[t->offset + 1] == '=') {
            t->offset += 2;
            return TK_LE;
        }
        else {
            t->offset += 1;
            return TK_LT;
        }
      case '!':
        if (t->input[t->offset + 1] == '=') {
            t->offset += 2;
            return TK_NE;
        }
        else {
            t->offset += 1;
            return TK_NOT;
        }
      case '&':
        if (t->input[t->offset + 1] == '&') {
            t->offset += 2;
            return TK_AND;
        }
        else {
            log_error(t->p->errh, __FILE__, __LINE__,
              "pos: %zu missing second &", t->offset+1);
            return -1;
        }
      case '|':
        if (t->input[t->offset + 1] == '|') {
            t->offset += 2;
            return TK_OR;
        }
        else {
            log_error(t->p->errh, __FILE__, __LINE__,
              "pos: %zu missing second |", t->offset+1);
            return -1;
        }
      case '(':
        t->offset++;
        t->in_brace++;
        return TK_LPARAN;
      case ')':
        t->offset++;
        t->in_brace--;
        return TK_RPARAN;
      case '\'':
        /* search for the terminating "'" */
        i = 1;
        while (t->input[t->offset + i] && t->input[t->offset + i] != '\'')
            ++i;
        if (t->input[t->offset + i]) {
            ssi_eval_expr_append_val(token, t->input + t->offset + 1, i-1);
            t->offset += i + 1;
            return TK_VALUE;
        }
        else {
            log_error(t->p->errh, __FILE__, __LINE__,
              "pos: %zu missing closing quote", t->offset+1);
            return -1;
        }
      case '$': {
        const char *var;
        size_t varlen;
        if (t->input[t->offset + 1] == '{') {
            i = 2;
            while (t->input[t->offset + i] && t->input[t->offset + i] != '}')
                ++i;
            if (t->input[t->offset + i] != '}') {
                log_error(t->p->errh, __FILE__, __LINE__,
                  "pos: %zu missing closing curly-brace", t->offset+1);
                return -1;
            }
            ++i; /* step past '}' */
            var = t->input + t->offset + 2;
            varlen = i-3;
        }
        else {
            for (i = 1; light_isalpha(t->input[t->offset + i]) ||
                    t->input[t->offset + i] == '_' ||
                    ((i > 1) && light_isdigit(t->input[t->offset + i])); ++i) ;
            var = t->input + t->offset + 1;
            varlen = i-1;
        }

        const data_string *ds;
        if ((ds = (const data_string *)
                  array_get_element_klen(t->p->ssi_cgi_env, var, varlen))
            || (ds = (const data_string *)
                     array_get_element_klen(t->p->ssi_vars, var, varlen)))
            ssi_eval_expr_append_val(token, BUF_PTR_LEN(&ds->value));
        t->offset += i;
        return TK_VALUE;
      }
      default:
        for (i = 0; isgraph(((unsigned char *)t->input)[t->offset + i]); ++i) {
            char d = t->input[t->offset + i];
            switch(d) {
            default: continue;
            case ' ':
            case '\t':
            case ')':
            case '(':
            case '\'':
            case '=':
            case '!':
            case '<':
            case '>':
            case '&':
            case '|':
                break;
            }
            break;
        }
        ssi_eval_expr_append_val(token, t->input + t->offset, i);
        t->offset += i;
        return TK_VALUE;
    }
}

static int ssi_eval_expr_loop(ssi_tokenizer_t * const t, ssi_val_t * const v);

static int ssi_eval_expr_step(ssi_tokenizer_t * const t, ssi_val_t * const v) {
    buffer_clear(&v->str);
    v->type = SSI_TYPE_UNSET; /*(not SSI_TYPE_BOOL)*/
    int next;
    const int level = t->in_brace;
    switch ((next = ssi_expr_tokenizer(t, &v->str))) {
      case TK_VALUE:
        do { next = ssi_expr_tokenizer(t, &v->str); } while (next == TK_VALUE);
        return next;
      case TK_LPARAN:
        if (t->in_brace > 16) return -1; /*(arbitrary limit)*/
        next = ssi_eval_expr_loop(t, v);
        if (next == TK_RPARAN && level == t->in_brace) {
            int result = ssi_val_to_bool(v);
            next = ssi_eval_expr_step(t, v); /*(resets v)*/
            v->bo = result;
            v->type = SSI_TYPE_BOOL;
            return (next==TK_AND || next==TK_OR || next==TK_RPARAN || 0==next)
              ? next
              : -1;
        }
        else
            return -1;
      case TK_RPARAN:
        return t->in_brace >= 0 ? TK_RPARAN : -1;
      case TK_NOT:
        if (++t->depth > 16) return -1; /*(arbitrary limit)*/
        next = ssi_eval_expr_step(t, v);
        --t->depth;
        if (-1 == next) return next;
        v->bo = !ssi_val_to_bool(v);
        v->type = SSI_TYPE_BOOL;
        return next;
      default:
        return next;
    }
}

static int ssi_eval_expr_loop_cmp(ssi_tokenizer_t * const t, ssi_val_t * const v1, int cond) {
    ssi_val_t v2 = { { NULL, 0, 0 }, SSI_TYPE_UNSET, 0 };
    int next = ssi_eval_expr_step(t, &v2);
    if (-1 != next) {
        v1->bo = ssi_eval_expr_cmp(v1, &v2, cond);
        v1->type = SSI_TYPE_BOOL;
    }
    buffer_free_ptr(&v2.str);
    return next;
}

static int ssi_eval_expr_loop(ssi_tokenizer_t * const t, ssi_val_t * const v1) {
    int next = ssi_eval_expr_step(t, v1);
    switch (next) {
      case TK_AND: case TK_OR:
        break;
      case TK_EQ:  case TK_NE:
      case TK_GT:  case TK_GE:
      case TK_LT:  case TK_LE:
        next = ssi_eval_expr_loop_cmp(t, v1, next);
        if (next == TK_RPARAN || 0 == next) return next;
        if (next != TK_AND && next != TK_OR) {
            log_error(t->p->errh, __FILE__, __LINE__,
              "pos: %zu parser failed somehow near here", t->offset+1);
            return -1;
        }
        break;
      default:
        return next;
    }

    /*(Note: '&&' and '||' evaluations are not short-circuited)*/
    ssi_val_t v2 = { { NULL, 0, 0 }, SSI_TYPE_UNSET, 0 };
    do {
        int cond = next;
        next = ssi_eval_expr_step(t, &v2);
        switch (next) {
          case TK_AND: case TK_OR: case 0:
            break;
          case TK_EQ:  case TK_NE:
          case TK_GT:  case TK_GE:
          case TK_LT:  case TK_LE:
            next = ssi_eval_expr_loop_cmp(t, &v2, next);
            if (-1 == next) continue;
            break;
          case TK_RPARAN:
            break;
          default:
            continue;
        }
        v1->bo = ssi_eval_expr_cmp_bool(v1, &v2, cond);
        v1->type = SSI_TYPE_BOOL;
    } while (next == TK_AND || next == TK_OR);
    buffer_free_ptr(&v2.str);
    return next;
}

static int ssi_eval_expr(handler_ctx *p, const char *expr) {
    ssi_tokenizer_t t;
    t.input = expr;
    t.offset = 0;
    t.size = strlen(expr);
    t.in_brace = 0;
    t.depth = 0;
    t.p = p;

    ssi_val_t v = { { NULL, 0, 0 }, SSI_TYPE_UNSET, 0 };
    int rc = ssi_eval_expr_loop(&t, &v);
    rc = (0 == rc && 0 == t.in_brace && 0 == t.depth)
      ? ssi_val_to_bool(&v)
      : -1;
    buffer_free_ptr(&v.str);

    return rc;
}




static int ssi_env_add(void *venv, const char *key, size_t klen, const char *val, size_t vlen) {
	array_set_key_value((array *)venv, key, klen, val, vlen);
	return 0;
}

static int build_ssi_cgi_vars(request_st * const r, handler_ctx * const p) {
	http_cgi_opts opts = { 0, 0, NULL, NULL };
	/* temporarily remove Authorization from request headers
	 * so that Authorization does not end up in SSI environment */
	buffer *vb_auth = http_header_request_get(r, HTTP_HEADER_AUTHORIZATION, CONST_STR_LEN("Authorization"));
	buffer b_auth;
	if (vb_auth) {
		memcpy(&b_auth, vb_auth, sizeof(buffer));
		memset(vb_auth, 0, sizeof(buffer));
	}

	array_reset_data_strings(p->ssi_cgi_env);

	if (0 != http_cgi_headers(r, &opts, ssi_env_add, p->ssi_cgi_env)) {
		r->http_status = 400;
		return -1;
	}

	if (vb_auth) {
		memcpy(vb_auth, &b_auth, sizeof(buffer));
	}

	return 0;
}

static void mod_ssi_timefmt (buffer * const b, buffer *timefmtb, unix_time64_t t, int localtm) {
    struct tm tm;
    const char * const timefmt = buffer_is_blank(timefmtb)
      ?
     #ifdef __MINGW32__
        "%a, %d %b %Y %H:%M:%S %Z"
     #else
        "%a, %d %b %Y %T %Z"
     #endif
      : timefmtb->ptr;
    buffer_append_strftime(b, timefmt, localtm
                                       ? localtime64_r(&t, &tm)
                                       : gmtime64_r(&t, &tm));
    if (buffer_is_blank(b))
        buffer_copy_string_len(b, CONST_STR_LEN("(none)"));
}

static int mod_ssi_process_file(request_st *r, handler_ctx *p, struct stat *st);

static int process_ssi_stmt(request_st * const r, handler_ctx * const p, const char ** const l, size_t n, struct stat * const st) {

	/**
	 * <!--#element attribute=value attribute=value ... -->
	 *
	 * config       DONE
	 *   errmsg     -- missing
	 *   sizefmt    DONE
	 *   timefmt    DONE
	 * echo         DONE
	 *   var        DONE
	 *   encoding   -- missing
	 * exec         DONE
	 *   cgi        -- never
	 *   cmd        DONE
	 * fsize        DONE
	 *   file       DONE
	 *   virtual    DONE
	 * flastmod     DONE
	 *   file       DONE
	 *   virtual    DONE
	 * include      DONE
	 *   file       DONE
	 *   virtual    DONE
	 * printenv     DONE
	 * set          DONE
	 *   var        DONE
	 *   value      DONE
	 *
	 * if           DONE
	 * elif         DONE
	 * else         DONE
	 * endif        DONE
	 *
	 *
	 * expressions
	 * AND, OR      DONE
	 * comp         DONE
	 * ${...}       -- missing
	 * $...         DONE
	 * '...'        DONE
	 * ( ... )      DONE
	 *
	 *
	 *
	 * ** all DONE **
	 * DATE_GMT
	 *   The current date in Greenwich Mean Time.
	 * DATE_LOCAL
	 *   The current date in the local time zone.
	 * DOCUMENT_NAME
	 *   The filename (excluding directories) of the document requested by the user.
	 * DOCUMENT_URI
	 *   The (%-decoded) URL path of the document requested by the user. Note that in the case of nested include files, this is not then URL for the current document.
	 * LAST_MODIFIED
	 *   The last modification date of the document requested by the user.
	 * USER_NAME
	 *   Contains the owner of the file which included it.
	 *
	 */

	size_t i, ssicmd = 0;
	buffer *tb = NULL;

	static const struct {
		const char *var;
		enum { SSI_UNSET, SSI_ECHO, SSI_FSIZE, SSI_INCLUDE, SSI_FLASTMOD,
				SSI_CONFIG, SSI_PRINTENV, SSI_SET, SSI_IF, SSI_ELIF,
				SSI_ELSE, SSI_ENDIF, SSI_EXEC, SSI_COMMENT } type;
	} ssicmds[] = {
		{ "echo",     SSI_ECHO },
		{ "include",  SSI_INCLUDE },
		{ "flastmod", SSI_FLASTMOD },
		{ "fsize",    SSI_FSIZE },
		{ "config",   SSI_CONFIG },
		{ "printenv", SSI_PRINTENV },
		{ "set",      SSI_SET },
		{ "if",       SSI_IF },
		{ "elif",     SSI_ELIF },
		{ "endif",    SSI_ENDIF },
		{ "else",     SSI_ELSE },
		{ "exec",     SSI_EXEC },
		{ "comment",  SSI_COMMENT },

		{ NULL, SSI_UNSET }
	};

	for (i = 0; ssicmds[i].var; i++) {
		if (0 == strcmp(l[1], ssicmds[i].var)) {
			ssicmd = ssicmds[i].type;
			break;
		}
	}

	chunkqueue * const cq = &p->wq;

	switch(ssicmd) {
	case SSI_ECHO: {
		/* echo */
		int var = 0;
		/* int enc = 0; */
		const char *var_val = NULL;

		static const struct {
			const char *var;
			enum {
				SSI_ECHO_UNSET,
				SSI_ECHO_DATE_GMT,
				SSI_ECHO_DATE_LOCAL,
				SSI_ECHO_DOCUMENT_NAME,
				SSI_ECHO_DOCUMENT_URI,
				SSI_ECHO_LAST_MODIFIED,
				SSI_ECHO_USER_NAME,
				SSI_ECHO_SCRIPT_URI,
				SSI_ECHO_SCRIPT_URL,
			} type;
		} echovars[] = {
			{ "DATE_GMT",      SSI_ECHO_DATE_GMT },
			{ "DATE_LOCAL",    SSI_ECHO_DATE_LOCAL },
			{ "DOCUMENT_NAME", SSI_ECHO_DOCUMENT_NAME },
			{ "DOCUMENT_URI",  SSI_ECHO_DOCUMENT_URI },
			{ "LAST_MODIFIED", SSI_ECHO_LAST_MODIFIED },
			{ "USER_NAME",     SSI_ECHO_USER_NAME },
			{ "SCRIPT_URI",    SSI_ECHO_SCRIPT_URI },
			{ "SCRIPT_URL",    SSI_ECHO_SCRIPT_URL },

			{ NULL, SSI_ECHO_UNSET }
		};

/*
		static const struct {
			const char *var;
			enum { SSI_ENC_UNSET, SSI_ENC_URL, SSI_ENC_NONE, SSI_ENC_ENTITY } type;
		} encvars[] = {
			{ "url",          SSI_ENC_URL },
			{ "none",         SSI_ENC_NONE },
			{ "entity",       SSI_ENC_ENTITY },

			{ NULL, SSI_ENC_UNSET }
		};
*/

		for (i = 2; i < n; i += 2) {
			if (0 == strcmp(l[i], "var")) {
				int j;

				var_val = l[i+1];

				for (j = 0; echovars[j].var; j++) {
					if (0 == strcmp(l[i+1], echovars[j].var)) {
						var = echovars[j].type;
						break;
					}
				}
			} else if (0 == strcmp(l[i], "encoding")) {
/*
				int j;

				for (j = 0; encvars[j].var; j++) {
					if (0 == strcmp(l[i+1], encvars[j].var)) {
						enc = encvars[j].type;
						break;
					}
				}
*/
			} else {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "ssi: unknown attribute for %s %s", l[1], l[i]);
			}
		}

		if (p->if_is_false) break;

		if (!var_val) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "ssi: %s var is missing", l[1]);
			break;
		}

		switch(var) {
		case SSI_ECHO_USER_NAME: {
			tb = r->tmp_buf;
			buffer_clear(tb);
#ifdef HAVE_PWD_H
			struct passwd *pw;
			if (NULL == (pw = getpwuid(st->st_uid))) {
				buffer_append_int(tb, st->st_uid);
			} else {
				buffer_copy_string(tb, pw->pw_name);
			}
#else
			buffer_append_int(tb, st->st_uid);
#endif
			chunkqueue_append_mem(cq, BUF_PTR_LEN(tb));
			break;
		}
		case SSI_ECHO_LAST_MODIFIED:
		case SSI_ECHO_DATE_LOCAL:
		case SSI_ECHO_DATE_GMT:
			tb = r->tmp_buf;
			buffer_clear(tb);
			mod_ssi_timefmt(tb, p->timefmt,
			                (var == SSI_ECHO_LAST_MODIFIED)
			                  ? st->st_mtime
			                  : log_epoch_secs,
			                (var != SSI_ECHO_DATE_GMT));
			chunkqueue_append_mem(cq, BUF_PTR_LEN(tb));
			break;
		case SSI_ECHO_DOCUMENT_NAME: {
			char *sl;

			if (NULL == (sl = strrchr(r->physical.path.ptr, '/'))) {
				chunkqueue_append_mem(cq, BUF_PTR_LEN(&r->physical.path));
			} else {
				chunkqueue_append_mem(cq, sl + 1, strlen(sl + 1));
			}
			break;
		}
		case SSI_ECHO_DOCUMENT_URI: {
			chunkqueue_append_mem(cq, BUF_PTR_LEN(&r->uri.path));
			break;
		}
		case SSI_ECHO_SCRIPT_URI: {
			if (!buffer_is_blank(&r->uri.scheme) && !buffer_is_blank(&r->uri.authority)) {
				chunkqueue_append_mem(cq, BUF_PTR_LEN(&r->uri.scheme));
				chunkqueue_append_mem(cq, CONST_STR_LEN("://"));
				chunkqueue_append_mem(cq, BUF_PTR_LEN(&r->uri.authority));
				chunkqueue_append_mem(cq, BUF_PTR_LEN(&r->target));
				if (!buffer_is_blank(&r->uri.query)) {
					chunkqueue_append_mem(cq, CONST_STR_LEN("?"));
					chunkqueue_append_mem(cq, BUF_PTR_LEN(&r->uri.query));
				}
			}
			break;
		}
		case SSI_ECHO_SCRIPT_URL: {
			chunkqueue_append_mem(cq, BUF_PTR_LEN(&r->target));
			if (!buffer_is_blank(&r->uri.query)) {
				chunkqueue_append_mem(cq, CONST_STR_LEN("?"));
				chunkqueue_append_mem(cq, BUF_PTR_LEN(&r->uri.query));
			}
			break;
		}
		default: {
			const data_string *ds;
			/* check if it is a cgi-var or a ssi-var */

			if (NULL != (ds = (const data_string *)array_get_element_klen(p->ssi_cgi_env, var_val, strlen(var_val))) ||
			    NULL != (ds = (const data_string *)array_get_element_klen(p->ssi_vars, var_val, strlen(var_val)))) {
				chunkqueue_append_mem(cq, BUF_PTR_LEN(&ds->value));
			} else {
				chunkqueue_append_mem(cq, CONST_STR_LEN("(none)"));
			}

			break;
		}
		}
		break;
	}
	case SSI_INCLUDE:
	case SSI_FLASTMOD:
	case SSI_FSIZE: {
		const char * file_path = NULL, *virt_path = NULL;
		struct stat stb;

		for (i = 2; i < n; i += 2) {
			if (0 == strcmp(l[i], "file")) {
				file_path = l[i+1];
			} else if (0 == strcmp(l[i], "virtual")) {
				virt_path = l[i+1];
			} else {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "ssi: unknown attribute for %s %s", l[1], l[i]);
			}
		}

		if (!file_path && !virt_path) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "ssi: %s file or virtual is missing", l[1]);
			break;
		}

		if (file_path && virt_path) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "ssi: %s only one of file and virtual is allowed here", l[1]);
			break;
		}


		if (p->if_is_false) break;

		tb = r->tmp_buf;

		if (file_path) {
			/* current doc-root */
			buffer_copy_string(tb, file_path);
			buffer_urldecode_path(tb);
			if (!buffer_is_valid_UTF8(tb)) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "SSI invalid UTF-8 after url-decode: %s", tb->ptr);
				break;
			}
			buffer_path_simplify(tb);
			char *sl = strrchr(r->physical.path.ptr, '/');
			if (NULL == sl) break; /*(not expected)*/
			buffer_copy_path_len2(p->stat_fn,
			                      r->physical.path.ptr,
			                      sl - r->physical.path.ptr + 1,
			                      BUF_PTR_LEN(tb));
		} else {
			/* virtual */

			buffer_clear(tb);
			if (virt_path[0] != '/') {
				/* there is always a / */
				const char * const sl = strrchr(r->uri.path.ptr, '/');
				buffer_copy_string_len(tb, r->uri.path.ptr, sl - r->uri.path.ptr + 1);
			}
			buffer_append_string(tb, virt_path);

			buffer_urldecode_path(tb);
			if (!buffer_is_valid_UTF8(tb)) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "SSI invalid UTF-8 after url-decode: %s", tb->ptr);
				break;
			}
			buffer_path_simplify(tb);

			/* we have an uri */

			/* Destination physical path (similar to code in mod_webdav.c)
			 * src r->physical.path might have been remapped with mod_alias, mod_userdir.
			 *   (but neither modifies r->physical.rel_path)
			 * Find matching prefix to support relative paths to current physical path.
			 * Aliasing of paths underneath current r->physical.basedir might not work.
			 * Likewise, mod_rewrite URL rewriting might thwart this comparison.
			 * Use mod_redirect instead of mod_alias to remap paths *under* this basedir.
			 * Use mod_redirect instead of mod_rewrite on *any* parts of path to basedir.
			 * (Related, use mod_auth to protect this basedir, but avoid attempting to
			 *  use mod_auth on paths underneath this basedir, as target path is not
			 *  validated with mod_auth)
			 */

			/* find matching URI prefix
			 * check if remaining r->physical.rel_path matches suffix
			 *   of r->physical.basedir so that we can use it to
			 *   remap Destination physical path */
			{
				const char *sep, *sep2;
				sep = r->uri.path.ptr;
				sep2 = tb->ptr;
				for (i = 0; sep[i] && sep[i] == sep2[i]; ++i) ;
				while (i != 0 && sep[--i] != '/') ; /* find matching directory path */
			}
			if (r->conf.force_lowercase_filenames) {
				buffer_to_lower(tb);
			}
			uint32_t remain = buffer_clen(&r->uri.path) - i;
			uint32_t plen = buffer_clen(&r->physical.path);
			if (plen >= remain
			    && (!r->conf.force_lowercase_filenames
			        ?         0 == memcmp(r->physical.path.ptr+plen-remain, r->physical.rel_path.ptr+i, remain)
			        : buffer_eq_icase_ssn(r->physical.path.ptr+plen-remain, r->physical.rel_path.ptr+i, remain))) {
				buffer_copy_path_len2(p->stat_fn,
				                      r->physical.path.ptr,
				                      plen-remain,
				                      tb->ptr+i,
				                      buffer_clen(tb)-i);
			} else {
				/* unable to perform physical path remap here;
				 * assume doc_root/rel_path and no remapping */
				buffer_copy_path_len2(p->stat_fn,
				                      BUF_PTR_LEN(&r->physical.doc_root),
				                      BUF_PTR_LEN(tb));
			}
		}

		if (!r->conf.follow_symlink
		    && 0 != stat_cache_path_contains_symlink(p->stat_fn, r->conf.errh)) {
			break;
		}

		int fd = stat_cache_open_rdonly_fstat(p->stat_fn, &stb, r->conf.follow_symlink);
		if (fd >= 0) {
			switch (ssicmd) {
			case SSI_FSIZE:
				buffer_clear(tb);
				if (p->sizefmt) {
					int j = 0;
					const char *abr[] = { " B", " kB", " MB", " GB", " TB", NULL };

					off_t s = stb.st_size;

					for (j = 0; s > 1024 && abr[j+1]; s /= 1024, j++);

					buffer_append_int(tb, s);
					buffer_append_string_len(tb, abr[j], j ? 3 : 2);
				} else {
					buffer_append_int(tb, stb.st_size);
				}
				chunkqueue_append_mem(cq, BUF_PTR_LEN(tb));
				break;
			case SSI_FLASTMOD:
				buffer_clear(tb);
				mod_ssi_timefmt(tb, p->timefmt, stb.st_mtime, 1);
				chunkqueue_append_mem(cq, BUF_PTR_LEN(tb));
				break;
			case SSI_INCLUDE:
				/* Keep the newest mtime of included files */
				if (include_file_last_mtime < TIME64_CAST(stb.st_mtime))
					include_file_last_mtime = TIME64_CAST(stb.st_mtime);

				if (file_path || 0 == p->conf.ssi_recursion_max) {
					/* don't process if #include file="..." is used */
					chunkqueue_append_file_fd(cq, p->stat_fn, fd, 0, stb.st_size);
					fd = -1;
				} else {
					buffer upsave, ppsave, prpsave;

					/* only allow predefined recursion depth */
					if (p->ssi_recursion_depth >= p->conf.ssi_recursion_max) {
						chunkqueue_append_mem(cq, CONST_STR_LEN("(error: include directives recurse deeper than pre-defined ssi.recursion-max)"));
						break;
					}

					/* prevents simple infinite loop */
					if (buffer_is_equal(&r->physical.path, p->stat_fn)) {
						chunkqueue_append_mem(cq, CONST_STR_LEN("(error: include directives create an infinite loop)"));
						break;
					}

					/* save and restore r->physical.path, r->physical.rel_path, and r->uri.path around include
					 *
					 * tb contains url-decoded, path-simplified, and lowercased (if r->conf.force_lowercase) uri path of target.
					 * r->uri.path and r->physical.rel_path are set to the same since we only operate on filenames here,
					 * not full re-run of all modules for subrequest */
					upsave = r->uri.path;
					ppsave = r->physical.path;
					prpsave = r->physical.rel_path;

					r->physical.path = *p->stat_fn;
					memset(p->stat_fn, 0, sizeof(buffer));

					memset(&r->uri.path, 0, sizeof(buffer));
					buffer_copy_buffer(&r->uri.path, tb);
					r->physical.rel_path = r->uri.path;

					close(fd);
					fd = -1;

					/*(ignore return value; muddle along as best we can if error occurs)*/
					++p->ssi_recursion_depth;
					mod_ssi_process_file(r, p, &stb);
					--p->ssi_recursion_depth;

					free(r->uri.path.ptr);
					r->uri.path = upsave;
					r->physical.rel_path = prpsave;

					free(p->stat_fn->ptr);
					*p->stat_fn = r->physical.path;
					r->physical.path = ppsave;
				}

				break;
			}

			if (fd >= 0) close(fd);
		} else {
			log_perror(r->conf.errh, __FILE__, __LINE__,
			  "ssi: stating %s failed", p->stat_fn->ptr);
		}
		break;
	}
	case SSI_SET: {
		const char *key = NULL, *val = NULL;
		for (i = 2; i < n; i += 2) {
			if (0 == strcmp(l[i], "var")) {
				key = l[i+1];
			} else if (0 == strcmp(l[i], "value")) {
				val = l[i+1];
			} else {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "ssi: unknown attribute for %s %s", l[1], l[i]);
			}
		}

		if (p->if_is_false) break;

		if (key && val) {
			array_set_key_value(p->ssi_vars, key, strlen(key), val, strlen(val));
		} else if (key || val) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "ssi: var and value have to be set in <!--#set %s=%s -->", l[1], l[2]);
		} else {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "ssi: var and value have to be set in <!--#set var=... value=... -->");
		}
		break;
	}
	case SSI_CONFIG:
		if (p->if_is_false) break;

		for (i = 2; i < n; i += 2) {
			if (0 == strcmp(l[i], "timefmt")) {
				buffer_copy_string(p->timefmt, l[i+1]);
			} else if (0 == strcmp(l[i], "sizefmt")) {
				if (0 == strcmp(l[i+1], "abbrev")) {
					p->sizefmt = 1;
				} else if (0 == strcmp(l[i+1], "bytes")) {
					p->sizefmt = 0;
				} else {
					log_error(r->conf.errh, __FILE__, __LINE__,
					  "ssi: unknown value for attribute '%s' for %s %s",
					  l[i], l[1], l[i+1]);
				}
			} else {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "ssi: unknown attribute for %s %s", l[1], l[i]);
			}
		}
		break;
	case SSI_PRINTENV:
		if (p->if_is_false) break;

		tb = r->tmp_buf;
		buffer_clear(tb);
		for (i = 0; i < p->ssi_vars->used; i++) {
			data_string *ds = (data_string *)p->ssi_vars->sorted[i];

			buffer_append_str2(tb, BUF_PTR_LEN(&ds->key), CONST_STR_LEN("="));
			buffer_append_string_encoded(tb, BUF_PTR_LEN(&ds->value), ENCODING_MINIMAL_XML);
			buffer_append_char(tb, '\n');
		}
		for (i = 0; i < p->ssi_cgi_env->used; i++) {
			data_string *ds = (data_string *)p->ssi_cgi_env->sorted[i];

			buffer_append_str2(tb, BUF_PTR_LEN(&ds->key), CONST_STR_LEN("="));
			buffer_append_string_encoded(tb, BUF_PTR_LEN(&ds->value), ENCODING_MINIMAL_XML);
			buffer_append_char(tb, '\n');
		}
		chunkqueue_append_mem(cq, BUF_PTR_LEN(tb));
		break;
	case SSI_EXEC: {
		const char *cmd = NULL;
		pid_t pid;
		chunk *c;
		log_error_st *errh = p->errh;

		if (!p->conf.ssi_exec) { /* <!--#exec ... --> disabled by config */
			break;
		}

		for (i = 2; i < n; i += 2) {
			if (0 == strcmp(l[i], "cmd")) {
				cmd = l[i+1];
			} else {
				log_error(errh, __FILE__, __LINE__,
				  "ssi: unknown attribute for %s %s", l[1], l[i]);
			}
		}

		if (p->if_is_false) break;

		/*
		 * as exec is assumed evil it is implemented synchronously
		 */

		if (!cmd) break;

		/* send cmd output to a temporary file */
		if (0 != chunkqueue_append_mem_to_tempfile(cq, "", 0, errh)) break;
		c = cq->last;
		off_t flen = c->file.length;
		if (flen && flen != lseek(c->file.fd, flen, SEEK_SET))
			log_perror(errh, __FILE__, __LINE__, "lseek failed");

		int status = 0;
		struct stat stb;
		stb.st_size = flen;
		/*(expects STDIN_FILENO open to /dev/null)*/
		int serrh_fd = r->conf.serrh ? r->conf.serrh->fd : -1;
		pid = fdevent_sh_exec(cmd, NULL, -1, c->file.fd, serrh_fd);
		if (-1 == pid) {
			log_perror(errh, __FILE__, __LINE__, "spawning exec failed: %s", cmd);
		} else if (fdevent_waitpid(pid, &status, 0) < 0) {
			log_perror(errh, __FILE__, __LINE__, "waitpid failed");
		} else {
			/* wait for the client to end */
			/* NOTE: synchronous; blocks entire lighttpd server */

			/*
			 * OpenBSD and Solaris send a EINTR on SIGCHILD even if we ignore it
			 */
			if (!WIFEXITED(status)) {
				log_error(errh, __FILE__, __LINE__, "process exited abnormally: %s", cmd);
			}
			if (0 == fstat(c->file.fd, &stb)) {
			}
		}
		chunkqueue_update_file(cq, c, stb.st_size - flen);
		break;
	}
	case SSI_IF: {
		const char *expr = NULL;

		for (i = 2; i < n; i += 2) {
			if (0 == strcmp(l[i], "expr")) {
				expr = l[i+1];
			} else {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "ssi: unknown attribute for %s %s", l[1], l[i]);
			}
		}

		if (!expr) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "ssi: %s expr missing", l[1]);
			break;
		}

		if ((!p->if_is_false) &&
		    ((p->if_is_false_level == 0) ||
		     (p->if_level < p->if_is_false_level))) {
			switch (ssi_eval_expr(p, expr)) {
			case -1:
			case 0:
				p->if_is_false = 1;
				p->if_is_false_level = p->if_level;
				break;
			case 1:
				p->if_is_false = 0;
				break;
			}
		}

		p->if_level++;

		break;
	}
	case SSI_ELSE:
		p->if_level--;

		if (p->if_is_false) {
			if ((p->if_level == p->if_is_false_level) &&
			    (p->if_is_false_endif == 0)) {
				p->if_is_false = 0;
			}
		} else {
			p->if_is_false = 1;

			p->if_is_false_level = p->if_level;
		}
		p->if_level++;

		break;
	case SSI_ELIF: {
		const char *expr = NULL;
		for (i = 2; i < n; i += 2) {
			if (0 == strcmp(l[i], "expr")) {
				expr = l[i+1];
			} else {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "ssi: unknown attribute for %s %s", l[1], l[i]);
			}
		}

		if (!expr) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "ssi: %s expr missing", l[1]);
			break;
		}

		p->if_level--;

		if (p->if_level == p->if_is_false_level) {
			if ((p->if_is_false) &&
			    (p->if_is_false_endif == 0)) {
				switch (ssi_eval_expr(p, expr)) {
				case -1:
				case 0:
					p->if_is_false = 1;
					p->if_is_false_level = p->if_level;
					break;
				case 1:
					p->if_is_false = 0;
					break;
				}
			} else {
				p->if_is_false = 1;
				p->if_is_false_level = p->if_level;
				p->if_is_false_endif = 1;
			}
		}

		p->if_level++;

		break;
	}
	case SSI_ENDIF:
		p->if_level--;

		if (p->if_level == p->if_is_false_level) {
			p->if_is_false = 0;
			p->if_is_false_endif = 0;
		}

		break;
	case SSI_COMMENT:
		break;
	default:
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "ssi: unknown ssi-command: %s", l[1]);
		break;
	}

	return 0;

}

__attribute_pure__
static int mod_ssi_parse_ssi_stmt_value(const unsigned char * const s, const int len) {
	int n;
	const int c = (s[0] == '"' ? '"' : s[0] == '\'' ? '\'' : 0);
	if (0 != c) {
		for (n = 1; n < len; ++n) {
			if (s[n] == c) return n+1;
			if (s[n] == '\\') {
				if (n+1 == len) return 0; /* invalid */
				++n;
			}
		}
		return 0; /* invalid */
	} else {
		for (n = 0; n < len; ++n) {
			if (isspace(s[n])) return n;
			if (s[n] == '\\') {
				if (n+1 == len) return 0; /* invalid */
				++n;
			}
		}
		return n;
	}
}

static int mod_ssi_parse_ssi_stmt_offlen(int o[10], const unsigned char * const s, const int len) {

	/**
	 * <!--#element attribute=value attribute=value ... -->
	 */

	/* s must begin "<!--#" and must end with "-->" */
	int n = 5;
	o[0] = n;
	for (; light_isalpha(s[n]); ++n) ; /*(n = 5 to begin after "<!--#")*/
	o[1] = n - o[0];
	if (0 == o[1]) return -1; /* empty token */

	if (n+3 == len) return 2; /* token only; no params */
	if (!isspace(s[n])) return -1;
	do { ++n; } while (isspace(s[n])); /* string ends "-->", so n < len */
	if (n+3 == len) return 2; /* token only; no params */

	o[2] = n;
	for (; light_isalpha(s[n]); ++n) ;
	o[3] = n - o[2];
	if (0 == o[3] || s[n++] != '=') return -1;

	o[4] = n;
	o[5] = mod_ssi_parse_ssi_stmt_value(s+n, len-n-3);
	if (0 == o[5]) return -1; /* empty or invalid token */
	n += o[5];

	if (n+3 == len) return 6; /* token and one param */
	if (!isspace(s[n])) return -1;
	do { ++n; } while (isspace(s[n])); /* string ends "-->", so n < len */
	if (n+3 == len) return 6; /* token and one param */

	o[6] = n;
	for (; light_isalpha(s[n]); ++n) ;
	o[7] = n - o[6];
	if (0 == o[7] || s[n++] != '=') return -1;

	o[8] = n;
	o[9] = mod_ssi_parse_ssi_stmt_value(s+n, len-n-3);
	if (0 == o[9]) return -1; /* empty or invalid token */
	n += o[9];

	if (n+3 == len) return 10; /* token and two params */
	if (!isspace(s[n])) return -1;
	do { ++n; } while (isspace(s[n])); /* string ends "-->", so n < len */
	if (n+3 == len) return 10; /* token and two params */
	return -1;
}

static void mod_ssi_parse_ssi_stmt(request_st * const r, handler_ctx * const p, char * const s, int len, struct stat * const st) {

	/**
	 * <!--#element attribute=value attribute=value ... -->
	 */

	int o[10];
	int m;
	const int n = mod_ssi_parse_ssi_stmt_offlen(o, (unsigned char *)s, len);
	char *l[6] = { s, NULL, NULL, NULL, NULL, NULL };
	if (-1 == n) {
		/* ignore <!--#comment ... --> */
		if (len >= 16
		    && 0 == memcmp(s+5, "comment", sizeof("comment")-1)
		    && (s[12] == ' ' || s[12] == '\t'))
			return;
		/* XXX: perhaps emit error comment instead of invalid <!--#...--> code to client */
		chunkqueue_append_mem(&p->wq, s, len); /* append stmt as-is */
		return;
	}

      #if 0
	/* dup s and then modify s */
	/*(l[0] is no longer used; was previously used in only one place for error reporting)*/
	l[0] = ck_malloc((size_t)(len+1));
	memcpy(l[0], s, (size_t)len);
	(l[0])[len] = '\0';
      #endif

	/* modify s in-place to split string into arg tokens */
	for (m = 0; m < n; m += 2) {
		char *ptr = s+o[m];
		switch (*ptr) {
		case '"':
		case '\'': (++ptr)[o[m+1]-2] = '\0'; break;
		default:       ptr[o[m+1]] = '\0';   break;
		}
		l[1+(m>>1)] = ptr;
		if (m == 4 || m == 8) {
			/* XXX: removing '\\' escapes from param value would be
			 * the right thing to do, but would potentially change
			 * current behavior, e.g. <!--#exec cmd=... --> */
		}
	}

	process_ssi_stmt(r, p, (const char **)l, 1+(n>>1), st);

      #if 0
	free(l[0]);
      #endif
}

static int mod_ssi_stmt_len(const char *s, const int len) {
	/* s must begin "<!--#" */
	int n, sq = 0, dq = 0, bs = 0;
	for (n = 5; n < len; ++n) { /*(n = 5 to begin after "<!--#")*/
		switch (s[n]) {
		default:
			break;
		case '-':
			if (!sq && !dq && n+2 < len && s[n+1] == '-' && s[n+2] == '>') return n+3; /* found end of stmt */
			break;
		case '"':
			if (!sq && (!dq || !bs)) dq = !dq;
			break;
		case '\'':
			if (!dq && (!sq || !bs)) sq = !sq;
			break;
		case '\\':
			if (sq || dq) bs = !bs;
			break;
		}
	}
	return 0; /* incomplete directive "<!--#...-->" */
}

static void mod_ssi_read_fd(request_st * const r, handler_ctx * const p, struct stat * const st, int fd) {
	ssize_t rd;
	size_t offset, pretag;
	/* allocate to reduce chance of stack exhaustion upon deep recursion */
	buffer * const b = chunk_buffer_acquire();
	chunkqueue * const cq = &p->wq;
	const size_t bufsz = 8192;
	chunk_buffer_prepare_append(b, bufsz-1);
	char * const buf = b->ptr;

	offset = 0;
	pretag = 0;
	while (0 < (rd = read(fd, buf+offset, bufsz-offset))) {
		char *s;
		size_t prelen = 0, len;
		offset += (size_t)rd;
		for (; (s = memchr(buf+prelen, '<', offset-prelen)); ++prelen) {
			prelen = s - buf;
			if (prelen + 5 <= offset) { /*("<!--#" is 5 chars)*/
				if (0 != memcmp(s+1, CONST_STR_LEN("!--#"))) continue; /* loop to loop for next '<' */

				if (prelen - pretag && !p->if_is_false) {
					chunkqueue_append_mem(cq, buf+pretag, prelen-pretag);
				}

				len = mod_ssi_stmt_len(buf+prelen, offset-prelen);
				if (len) { /* num of chars to be consumed */
					mod_ssi_parse_ssi_stmt(r, p, buf+prelen, len, st);
					prelen += (len - 1); /* offset to '>' at end of SSI directive; incremented at top of loop */
					pretag = prelen + 1;
					if (pretag == offset) {
						offset = pretag = 0;
						break;
					}
				} else if (0 == prelen && offset == bufsz) { /*(full buf)*/
					/* SSI statement is way too long
					 * NOTE: skipping this buf will expose *the rest* of this SSI statement */
					chunkqueue_append_mem(cq, CONST_STR_LEN("<!-- [an error occurred: directive too long] "));
					/* check if buf ends with "-" or "--" which might be part of "-->"
					 * (buf contains at least 5 chars for "<!--#") */
					if (buf[offset-2] == '-' && buf[offset-1] == '-') {
						chunkqueue_append_mem(cq, CONST_STR_LEN("--"));
					} else if (buf[offset-1] == '-') {
						chunkqueue_append_mem(cq, CONST_STR_LEN("-"));
					}
					offset = pretag = 0;
					break;
				} else { /* incomplete directive "<!--#...-->" */
					memmove(buf, buf+prelen, (offset -= prelen));
					pretag = 0;
					break;
				}
			} else if (prelen + 1 == offset || 0 == memcmp(s+1, "!--", offset - prelen - 1)) {
				if (prelen - pretag && !p->if_is_false) {
					chunkqueue_append_mem(cq, buf+pretag, prelen-pretag);
				}
				memmove(buf, buf+prelen, (offset -= prelen));
				pretag = 0;
				break;
			}
			/* loop to look for next '<' */
		}
		if (offset == bufsz) {
			if (!p->if_is_false) {
				chunkqueue_append_mem(cq, buf+pretag, offset-pretag);
			}
			offset = pretag = 0;
		}
		/* flush intermediate cq to r->write_queue (and possibly to
		 * temporary file) if last MEM_CHUNK has less than 1k-1 avail
		 * (reduce occurrence of copying to reallocate larger chunk) */
		if (cq->last && cq->last->type == MEM_CHUNK
		    && buffer_string_space(cq->last->mem) < 1023)
			if (0 != http_chunk_transfer_cqlen(r, cq, chunkqueue_length(cq)))
				chunkqueue_remove_empty_chunks(&r->write_queue);
				/*(likely unrecoverable error if r->resp_send_chunked)*/
	}

	if (0 != rd) {
		log_perror(r->conf.errh, __FILE__, __LINE__,
		  "read(): %s", r->physical.path.ptr);
	}

	if (offset - pretag) {
		/* copy remaining data in buf */
		if (!p->if_is_false) {
			chunkqueue_append_mem(cq, buf+pretag, offset-pretag);
		}
	}

	chunk_buffer_release(b);
	if (0 != http_chunk_transfer_cqlen(r, cq, chunkqueue_length(cq)))
		chunkqueue_remove_empty_chunks(&r->write_queue);
		/*(likely error unrecoverable if r->resp_send_chunked)*/
}


static int mod_ssi_process_file(request_st * const r, handler_ctx * const p, struct stat * const st) {
	int fd = stat_cache_open_rdonly_fstat(&r->physical.path, st, r->conf.follow_symlink);
	if (-1 == fd) {
		log_perror(r->conf.errh, __FILE__, __LINE__,
		  "open(): %s", r->physical.path.ptr);
		return -1;
	}

	mod_ssi_read_fd(r, p, st, fd);

	close(fd);
	return 0;
}


static int mod_ssi_handle_request(request_st * const r, handler_ctx * const p) {
	struct stat st;

	/* get a stream to the file */

	buffer_clear(p->timefmt);
	array_reset_data_strings(p->ssi_vars);
	array_reset_data_strings(p->ssi_cgi_env);
	build_ssi_cgi_vars(r, p);

	/* Reset the modified time of included files */
	include_file_last_mtime = 0;

	if (mod_ssi_process_file(r, p, &st)) return -1;

	r->resp_body_finished = 1;

	if (!p->conf.content_type) {
		http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
	} else {
		http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), BUF_PTR_LEN(p->conf.content_type));
	}

	if (p->conf.conditional_requests) {
		/* Generate "ETag" & "Last-Modified" headers */

		/* use most recently modified include file for ETag and Last-Modified */
		if (TIME64_CAST(st.st_mtime) < include_file_last_mtime)
			st.st_mtime = include_file_last_mtime;

		http_etag_create(r->tmp_buf, &st, r->conf.etag_flags);
		http_header_response_set(r, HTTP_HEADER_ETAG, CONST_STR_LEN("ETag"), BUF_PTR_LEN(r->tmp_buf));

		const buffer * const mtime = http_response_set_last_modified(r, TIME64_CAST(st.st_mtime));
		http_response_handle_cachable(r, mtime, TIME64_CAST(st.st_mtime));
	}

	/* Reset the modified time of included files */
	include_file_last_mtime = 0;

	return 0;
}

URIHANDLER_FUNC(mod_ssi_physical_path) {

	if (NULL != r->handler_module) return HANDLER_GO_ON;
	/* r->physical.path is non-empty for handle_subrequest_start */
	/*if (buffer_is_blank(&r->physical.path)) return HANDLER_GO_ON;*/

	plugin_config pconf;
	mod_ssi_patch_config(r, p_d, &pconf);
	if (NULL == pconf.ssi_extension) return HANDLER_GO_ON;

	if (array_match_value_suffix(pconf.ssi_extension, &r->physical.path)) {
		const plugin_data * const p = p_d;
		r->handler_module = p->self;
		r->plugin_ctx[p->id] = handler_ctx_init(&pconf, p_d, r->conf.errh);
	}

	return HANDLER_GO_ON;
}

SUBREQUEST_FUNC(mod_ssi_handle_subrequest) {
	handler_ctx *hctx = r->plugin_ctx[((const plugin_data *)p_d)->id];
	if (NULL == hctx) return HANDLER_GO_ON;
	/*
	 * NOTE: if mod_ssi modified to use fdevents, HANDLER_WAIT_FOR_EVENT,
	 * instead of blocking to completion, then hctx->timefmt, hctx->ssi_vars,
	 * and hctx->ssi_cgi_env should be allocated and cleaned up per request.
	 */

	return 0 == mod_ssi_handle_request(r, hctx)
	  ? HANDLER_FINISHED
	  : http_status_set_err(r, 500); /* Internal Server Error */
}

static handler_t mod_ssi_handle_request_reset(request_st * const r, void *p_d) {
	plugin_data *p = p_d;
	handler_ctx *hctx = r->plugin_ctx[p->id];
	if (hctx) {
		handler_ctx_free(hctx);
		r->plugin_ctx[p->id] = NULL;
	}

	return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_ssi_plugin_init(plugin *p);
int mod_ssi_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "ssi";

	p->init        = mod_ssi_init;
	p->handle_subrequest_start = mod_ssi_physical_path;
	p->handle_subrequest       = mod_ssi_handle_subrequest;
	p->handle_request_reset    = mod_ssi_handle_request_reset;
	p->set_defaults  = mod_ssi_set_defaults;
	p->cleanup     = mod_ssi_free;

	return 0;
}
