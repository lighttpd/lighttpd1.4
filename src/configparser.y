%token_prefix TK_
%token_type {buffer *}
%extra_argument {config_t *ctx}
%name configparser

%include {
#include <assert.h>
#include <stdio.h>
#include "config.h"
#include "configfile.h"
#include "buffer.h"
#include "array.h"

static void configparser_push(config_t *ctx, data_config *dc, int isnew) {
  if (isnew) {
    dc->context_ndx = ctx->all_configs->used;
    array_insert_unique(ctx->all_configs, (data_unset *)dc);
  }
  array_insert_unique(ctx->configs_stack, (data_unset *)ctx->current);
  ctx->current = dc;
}

static data_config *configparser_pop(config_t *ctx) {
  data_config *old = ctx->current;
  ctx->current = (data_config *) array_pop(ctx->configs_stack);
  return old;
}

}

%parse_failure {
  ctx->ok = 0;
}

input ::= metalines.
metalines ::= metalines metaline.
metalines ::= .
metaline ::= varline.
metaline ::= condlines EOL.
metaline ::= EOL.

%type value {data_unset *}
%type aelement {data_unset *}
%type aelements {array *}
%type array {array *}
%type condline {data_config *}
%type condlines {data_config *}
%type cond {config_cond_t }
%token_destructor { buffer_free($$); }

varline ::= key(A) ASSIGN value(B). {
  buffer_copy_string_buffer(B->key, A);
  if (NULL == array_get_element(ctx->current->value, B->key->ptr)) {
    array_insert_unique(ctx->current->value, B);
  } else {
    fprintf(stderr, "Duplicate config variable in conditional 1 %s: %s\n", 
            ctx->current->key->ptr, B->key->ptr);
    ctx->ok = 0;
    B->free(B);
  }
  buffer_free(A);
}

key(A) ::= LKEY(B). {
  A = B;
  B = NULL;
}

value(A) ::= STRING(B). {
  A = (data_unset *)data_string_init();
  buffer_copy_string_buffer(((data_string *)(A))->value, B);
  buffer_free(B);
}

value(A) ::= INTEGER(B). {
  A = (data_unset *)data_integer_init();
  ((data_integer *)(A))->value = strtol(B->ptr, NULL, 10);
  buffer_free(B);
}
value(A) ::= array(B). {
  A = (data_unset *)data_array_init();
  array_free(((data_array *)(A))->value);
  ((data_array *)(A))->value = B;
}
array(A) ::= LPARAN aelements(B) RPARAN. {
  A = B;
  B = NULL;
}

aelements(A) ::= aelements(C) COMMA aelement(B). {
  if (buffer_is_empty(B->key) ||
      NULL == array_get_element(C, B->key->ptr)) {
    array_insert_unique(C, B);
  } else {
    fprintf(stderr, "Duplicate array-key: %s\n", 
            B->key->ptr);
    B->free(B);
    ctx->ok = 0;
  }
  
  A = C;
}

aelements(A) ::= aelements(C) COMMA. {
  A = C;
}

aelements(A) ::= aelement(B). {
  A = array_init();
  array_insert_unique(A, B);
}

aelement(A) ::= value(B). {
  A = B;
  B = NULL;
}
aelement(A) ::= STRING(B) ARRAY_ASSIGN value(C). {
  buffer_copy_string_buffer(C->key, B);
  buffer_free(B);
  
  A = C;
  C = NULL;
}

eols ::= EOL.
eols ::= .

condlines(A) ::= condlines(B) eols OR condline(C). {
  assert(B->context_ndx < C->context_ndx);
  C->prev = B;
  B->next = C;
  A = C;
  B = NULL;
  C = NULL;
}

condlines(A) ::= condline(B). {
  A = B;
  B = NULL;
}

condline(A) ::= context LCURLY metalines RCURLY. {
  data_config *parent, *cur;
  
  cur = ctx->current;
  configparser_pop(ctx);
  parent = ctx->current;

  assert(cur && parent);

  if (0 != parent->context_ndx) { /* not global */
    assert(cur->context_ndx > parent->context_ndx);
    cur->parent = parent;
  }
  A = cur;
}

context ::= DOLLAR SRVVARNAME(B) LBRACKET STRING(C) RBRACKET cond(E) STRING(D). {
  data_config *dc;
  buffer *b;
  
  b = buffer_init();
  buffer_copy_string_buffer(b, ctx->current->key);
  buffer_append_string(b, "/");
  buffer_append_string_buffer(b, B);
  buffer_append_string_buffer(b, C);
  buffer_append_string_buffer(b, D);
  buffer_append_long(b, E);
  
  if (NULL != (dc = (data_config *)array_get_element(ctx->all_configs, b->ptr))) {
    configparser_push(ctx, dc, 0);
  } else {
    dc = data_config_init();
    
    buffer_copy_string_buffer(dc->key, b);
    buffer_copy_string_buffer(dc->comp_key, B);
    buffer_append_string_buffer(dc->comp_key, C);
    dc->cond = E;
    
    switch(E) {
    case CONFIG_COND_NE:
    case CONFIG_COND_EQ:
      dc->string = buffer_init_string(D->ptr);
      break;
    case CONFIG_COND_NOMATCH:
    case CONFIG_COND_MATCH: {
#ifdef HAVE_PCRE_H
      const char *errptr;
      int erroff;
      
      if (NULL == (dc->regex = 
          pcre_compile(D->ptr, 0, &errptr, &erroff, NULL))) {
	dc->string = buffer_init_string(errptr);
	dc->cond = CONFIG_COND_UNSET;
	
	ctx->ok = 0;
      } else if (NULL == (dc->regex_study = pcre_study(dc->regex, 0, &errptr)) &&  
                 errptr != NULL) {
        fprintf(stderr, "studying regex failed: %s -> %s\n", 
          D->ptr, errptr);
	ctx->ok = 0;
      }
#else
      fprintf(stderr, "regex conditionals are not allowed as pcre-support" \
                      "is missing: $%s[%s]\n", 
                      B->ptr, C->ptr);
      ctx->ok = 0;
#endif
      break;
    }

    default:
      fprintf(stderr, "unknown condition for $%s[%s]\n", 
                      B->ptr, C->ptr);
      ctx->ok = 0;
      break;
    }
    
    configparser_push(ctx, dc, 1);
  }
  buffer_free(b);
  buffer_free(B);
  buffer_free(C);
  buffer_free(D);
}
cond(A) ::= EQ. {
  A = CONFIG_COND_EQ;
}
cond(A) ::= MATCH. {
  A = CONFIG_COND_MATCH;
}
cond(A) ::= NE. {
  A = CONFIG_COND_NE;
}
cond(A) ::= NOMATCH. {
  A = CONFIG_COND_NOMATCH;
}
