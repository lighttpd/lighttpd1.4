%token_prefix TK_
%token_type {buffer *}
%extra_argument {config_t *ctx}
%name configparser

%include {
#include <assert.h>
#include "config.h"
#include "configfile.h"
#include "buffer.h"
#include "array.h"
}

%parse_failure {
  ctx->ok = 0;
}

input ::= metalines.
metalines ::= metalines metaline.
metalines ::= .
metaline ::= varline.
metaline ::= condline.
metaline ::= EOL.

%type value {data_unset *}
%type aelement {data_unset *}
%type aelements {array *}
%type array {array *}
%type cond {config_cond_t }
%token_destructor { buffer_free($$); }

varline ::= key(A) ASSIGN value(B). {
  buffer_copy_string_buffer(B->key, A);
  array_insert_unique(ctx->ctx_config, B);
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
  array_insert_unique(C, B);
  
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
condline ::= context LCURLY metalines RCURLY EOL. {
  data_config *dc;
  
  dc = (data_config *)array_get_element(ctx->config, "global");
  assert(dc);
  ctx->ctx_name = dc->key;
  ctx->ctx_config = dc->value;
}

context ::= DOLLAR SRVVARNAME(B) LBRACKET STRING(C) RBRACKET cond(E) STRING(D). {
  data_config *dc;
  buffer *b;
  
  b = buffer_init();
  buffer_copy_string_buffer(b, B);
  buffer_append_string_buffer(b, C);
  buffer_append_string_buffer(b, D);
  buffer_append_long(b, E);
  
  if (NULL != (dc = (data_config *)array_get_element(ctx->config, b->ptr))) {
    ctx->ctx_name = dc->key;
    ctx->ctx_config = dc->value;
  } else {
    dc = data_config_init();
    
    buffer_copy_string_buffer(dc->key, b);
    buffer_copy_string_buffer(dc->comp_key, B);
    buffer_append_string_buffer(dc->comp_key, C);
    dc->cond = E;
    
    switch(E) {
    case CONFIG_COND_NE:
    case CONFIG_COND_EQ:
      dc->match.string = buffer_init_string(D->ptr);
      break;
#ifdef HAVE_PCRE_H
    case CONFIG_COND_NOMATCH:
    case CONFIG_COND_MATCH: {
      const char *errptr;
      int erroff;
      
      if (NULL == (dc->match.regex = 
          pcre_compile(D->ptr, 0, &errptr, &erroff, NULL))) {
	dc->match.string = buffer_init_string(errptr);
	dc->cond = CONFIG_COND_UNSET;
      }
      break;
    }
#endif
    default:
      break;
    }
    
    array_insert_unique(ctx->config, (data_unset *)dc);
	
    ctx->ctx_name = dc->key;
    ctx->ctx_config = dc->value;
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
