#include "first.h"

#include "buffer.h"
#include "log.h"
#include "mod_ssi.h"
#include "mod_ssi_expr.h"
#include "mod_ssi_exprparser.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	const char *input;
	size_t offset;
	size_t size;

	int in_brace;
	int depth;
	handler_ctx *p;
} ssi_tokenizer_t;

ssi_val_t *ssi_val_init(void) {
	ssi_val_t *s;

	s = calloc(1, sizeof(*s));
	force_assert(s);
	s->str = buffer_init();

	return s;
}

void ssi_val_free(ssi_val_t *s) {
	if (s->str) buffer_free(s->str);

	free(s);
}

__attribute_pure__
int ssi_val_tobool(const ssi_val_t *B) {
    return B->type == SSI_TYPE_BOOL ? B->bo : !buffer_is_blank(B->str);
}

__attribute_pure__
static int ssi_eval_expr_cmp(const ssi_val_t * const v1, const ssi_val_t * const v2, const int cond) {
    int cmp = (v1->type != SSI_TYPE_BOOL && v2->type != SSI_TYPE_BOOL)
      ? strcmp(v1->str->ptr ? v1->str->ptr : "",
               v2->str->ptr ? v2->str->ptr : "")
      : ssi_val_tobool(v1) - ssi_val_tobool(v2);
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
      ? ssi_val_tobool(v1) || ssi_val_tobool(v2)  /* TK_OR */
      : ssi_val_tobool(v1) && ssi_val_tobool(v2); /* TK_AND */
}

static void ssi_eval_expr_append_val(buffer * const b, const char *s, const size_t slen) {
    if (buffer_is_blank(b))
        buffer_append_string_len(b, s, slen);
    else
        buffer_append_str2(b, CONST_STR_LEN(""), s, slen);
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
			} else {
				t->offset += 1;
				return TK_GT;
			}
		case '<':
			if (t->input[t->offset + 1] == '=') {
				t->offset += 2;
				return TK_LE;
			} else {
				t->offset += 1;
				return TK_LT;
			}
		case '!':
			if (t->input[t->offset + 1] == '=') {
				t->offset += 2;
				return TK_NE;
			} else {
				t->offset += 1;
				return TK_NOT;
			}
		case '&':
			if (t->input[t->offset + 1] == '&') {
				t->offset += 2;
				return TK_AND;
			} else {
				log_error(t->p->errh, __FILE__, __LINE__,
				  "pos: %zu missing second &", t->offset+1);
				return -1;
			}
		case '|':
			if (t->input[t->offset + 1] == '|') {
				t->offset += 2;
				return TK_OR;
			} else {
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
			for (i = 1; t->input[t->offset + i] && t->input[t->offset + i] != '\'';  i++);

			if (t->input[t->offset + i]) {
				ssi_eval_expr_append_val(token, t->input + t->offset + 1, i-1);
				t->offset += i + 1;
				return TK_VALUE;
			} else {
				log_error(t->p->errh, __FILE__, __LINE__,
				  "pos: %zu missing closing quote", t->offset+1);
				return -1;
			}
		case '$': {
			const char *var;
			size_t varlen;
			if (t->input[t->offset + 1] == '{') {
				for (i = 2; t->input[t->offset + i] && t->input[t->offset + i] != '}';  i++);

				if (t->input[t->offset + i] != '}') {
					log_error(t->p->errh, __FILE__, __LINE__,
					  "pos: %zu missing closing curly-brace", t->offset+1);
					return -1;
				}
				++i; /* step past '}' */
				var = t->input + t->offset + 2;
				varlen = i-3;
			} else {
				for (i = 1; isalpha(((unsigned char *)t->input)[t->offset + i]) ||
					    t->input[t->offset + i] == '_' ||
					    ((i > 1) && isdigit(((unsigned char *)t->input)[t->offset + i]));  i++);
				var = t->input + t->offset + 1;
				varlen = i-1;
			}

			const data_string *ds;
			if (NULL != (ds = (const data_string *)array_get_element_klen(t->p->ssi_cgi_env, var, varlen))
			    || NULL != (ds = (const data_string *)array_get_element_klen(t->p->ssi_vars, var, varlen)))
				ssi_eval_expr_append_val(token, BUF_PTR_LEN(&ds->value));
			t->offset += i;
			return TK_VALUE;
		}
		default:
			for (i = 0; isgraph(((unsigned char *)t->input)[t->offset + i]);  i++) {
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
    buffer_clear(v->str);
    v->type = SSI_TYPE_UNSET; /*(not SSI_TYPE_BOOL)*/
    int next;
    const int level = t->in_brace;
    switch ((next = ssi_expr_tokenizer(t, v->str))) {
      case TK_VALUE:
        do { next=ssi_expr_tokenizer(t, v->str); } while (next == TK_VALUE);
        return next;
      case TK_LPARAN:
        if (t->in_brace > 16) return -1; /*(arbitrary limit)*/
        next = ssi_eval_expr_loop(t, v);
        if (next == TK_RPARAN && level == t->in_brace) {
            int result = ssi_val_tobool(v);
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
        v->bo = !ssi_val_tobool(v);
        v->type = SSI_TYPE_BOOL;
        return next;
      default:
        return next;
    }
}

static int ssi_eval_expr_loop_cmp(ssi_tokenizer_t * const t, ssi_val_t * const v1, int cond) {
    ssi_val_t v2 = { SSI_TYPE_UNSET, NULL, 0 };
    v2.str = buffer_init();
    int next = ssi_eval_expr_step(t, &v2);
    if (-1 != next) {
        v1->bo = ssi_eval_expr_cmp(v1, &v2, cond);
        v1->type = SSI_TYPE_BOOL;
    }
    buffer_free(v2.str);
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
    ssi_val_t v2 = { SSI_TYPE_UNSET, NULL, 0 };
    v2.str = buffer_init();
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
            if (-1 != next)
                break;
            __attribute_fallthrough__
          default:
            buffer_free(v2.str);
            return next;
        }
        v1->bo = ssi_eval_expr_cmp_bool(v1, &v2, cond);
        v1->type = SSI_TYPE_BOOL;
    } while (next == TK_AND || next == TK_OR);
    buffer_free(v2.str);
    return next;
}

int ssi_eval_expr(handler_ctx *p, const char *expr) {
	ssi_tokenizer_t t;
	t.input = expr;
	t.offset = 0;
	t.size = strlen(expr);
	t.in_brace = 0;
	t.depth = 0;
	t.p = p;

	ssi_val_t v = { SSI_TYPE_UNSET, NULL, 0 };
	v.str = buffer_init();
	int rc = ssi_eval_expr_loop(&t, &v);
	rc = (0 == rc && 0 == t.in_brace && 0 == t.depth)
	  ? ssi_val_tobool(&v)
	  : -1;
	buffer_free(v.str);

	return rc;
}
