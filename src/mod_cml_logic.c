#include <sys/stat.h>
#include <time.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include "buffer.h"
#include "server.h"
#include "log.h"
#include "plugin.h"

#include "mod_cml.h"

#include "stream.h"

tnode_val *tnode_val_init() {
	tnode_val *tv;
	
	tv = calloc(1, sizeof(*tv));
	assert(tv);
	
	return tv;
}

int tnode_val_move(tnode_val *dst, tnode_val *src) {
	switch(src->type) {
	case T_NODE_VALUE_LONG:
		dst->data.lon = src->data.lon;
		break;
	case T_NODE_VALUE_STRING:
		dst->data.str = src->data.str;
		src->data.str = NULL;
		break;
	default:
		break;
	}
	
	dst->type = src->type;
	src->type = UNSET;
	
	return 0;
}

void tnode_val_free(tnode_val *tv) {
	switch(tv->type) {
	case T_NODE_VALUE_STRING:
		buffer_free(tv->data.str);
		break;
	default:
		break;
	}
	
	free(tv);
}

tnode_val_array *tnode_val_array_init() {
	tnode_val_array *tva;
	
	tva = calloc(1, sizeof(*tva));
	assert(tva);
	
	return tva;
}

int tnode_val_array_append(tnode_val_array *tva, tnode_val *val) {
	if (tva->size == 0) {
		tva->size = 4;
		tva->ptr = malloc(tva->size * sizeof(tnode_val *));
	} else if (tva->size == tva->used) {
		tva->size += 4;
		tva->ptr = realloc(tva->ptr, tva->size * sizeof(tnode_val *));
	}
	
	tva->ptr[tva->used++] = val;
	
	return 0;
}

void tnode_val_array_free(tnode_val_array *tva) {
	size_t i;
	if (!tva) return;
	
	for (i = 0; i < tva->used; i++) {
		tnode_val_free(tva->ptr[i]);
	}
	
	free(tva->ptr);
	free(tva);
}

void tnode_val_array_reset(tnode_val_array *tva) {
	size_t i;
	
	if (!tva) return;
	
	for (i = 0; i < tva->used; i++) {
		tnode_val_free(tva->ptr[i]);
	}
	
	tva->used = 0;
}


tnode *tnode_init() {
	tnode *t;
	
	t = calloc(1, sizeof(*t));
	assert(t);
	
	return t;
}

void tnode_free(tnode *t ) {
	if (IS_STRING(t)) {
		buffer_free(t->value.data.str);
	}
	
	if (t->r) tnode_free(t->r);
	if (t->l) tnode_free(t->l);
	
	free(t);
}

int tnode_prepare_long(tnode *t) {
	switch (t->value.type) {
	case T_NODE_VALUE_STRING:
		buffer_free(t->value.data.str);
		break;
	default:
		break;
	}
	
	t->value.type = T_NODE_VALUE_LONG;
	
	return 0;
}

int tnode_prepare_string(tnode *t) {
	switch (t->value.type) {
	case T_NODE_VALUE_STRING:
		buffer_reset(t->value.data.str);
		break;
	default:
		t->value.data.str = buffer_init();
		break;
	}
	
	t->value.type = T_NODE_VALUE_STRING;
	
	return 0;
}

int cache_trigger_parse(server *srv, connection *con, plugin_data *p, buffer *t /* trigger */, tnode *n) {
	size_t i, pre = 0, post = 0;
	int braces = 0;
	int quotes = 0;
	/* 
	 * unix.time.now - file.mtime("head.html") > 30 
	 */
	
	cache_trigger_functions f[] = {
		{ "file.mtime",     1, f_file_mtime },
		{ "unix.time.now",  0, f_unix_time_now },
		{ "memcache.exits", 1, f_memcache_exists },
		{ "memcache.get",   1, f_memcache_get },
		{ NULL, 0, NULL },
	};
	
	if (t->used == 0) {
		log_error_write(srv, __FILE__, __LINE__, "s", "empty term");
		return -1;
	}
	
	n->op = UNSET;
	
	/* search for the highest op */
	for (i = 0; i < t->used; i++) {
		switch(t->ptr[i]) {
		case '\\': 
			switch (t->ptr[i+1]) {
			case '"': if (quotes) i++; break;
			}
			break;
		case '"':
			quotes = quotes ? 0 : 1;
			
			break;
		}
		
		if (quotes) continue;
		
		switch(t->ptr[i]) {
		case '(': braces++; break;
		case ')': braces--; 
			if (braces < 0) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "braces don't match:", t->ptr);
				
					return -1;
			}
			break;
		}
		
		if (braces) continue;
		
		switch(t->ptr[i]) {
		case '-': if (MINUS >= n->op) { n->op = MINUS; pre = i - 1; post = i + 1; } break;
		case '+': if (PLUS  >= n->op) { n->op = PLUS;  pre = i - 1; post = i + 1; } break;
		case '*': if (TIMES >= n->op) { n->op = TIMES; pre = i - 1; post = i + 1; } break;
		case '/': if (PART  >= n->op) { n->op = PART;  pre = i - 1; post = i + 1; } break;
		case '>': 
			switch(t->ptr[i+1]) {
			case '=':
				if (GE > n->op) { n->op = GE; pre = i - 1; post = i + 2; } 
				i++;
				break;
			default:
				if (GT > n->op) { n->op = GT; pre = i - 1; post = i + 1; } 
				break;
			}
			break;
		case '<': 
			switch(t->ptr[i+1]) {
			case '=':
				if (LE > n->op) { n->op = LE; pre = i - 1; post = i + 2; } 
				i++;
				break;
			default:
				if (LT > n->op) { n->op = LT; pre = i - 1; post = i + 1; } 
				break;
			}
			break;
		case '!': 
			switch(t->ptr[i+1]) {
			case '=':
				if (NE > n->op) { n->op = NE; pre = i - 1; post = i + 2; } 
				i++;
				break;
			}
			break;
		case '&': 
			switch(t->ptr[i+1]) {
			case '&':
				if (AND > n->op) { n->op = AND; pre = i - 1; post = i + 2; } 
				i++;
				break;
			}
			break;
		case '|': 
			switch(t->ptr[i+1]) {
			case '|':
				if (OR > n->op) { n->op = OR; pre = i - 1; post = i + 2; } 
				i++;
				break;
			}
			break;
		case '=': if (EQ > n->op) { n->op = EQ; pre = i - 1; post = i + 1; } break;
		}
	}

	if (braces != 0) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "braces don't match:", t->ptr);
		
		return -1;
	}
	
	if (quotes != 0) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "quotes don't match:", t->ptr);
		
		return -1;
	}
	
	if (n->op != UNSET) {
		buffer *b;
		
		b = buffer_init();
		
		/* strip spaces */
		for (i = pre; t->ptr[i] == ' ' || t->ptr[i] == '\t'; i--);
		
		buffer_copy_string_len(b, t->ptr, i + 1);
		if (n->l == NULL) n->l = tnode_init();
		if (-1 == cache_trigger_parse(srv, con, p, b, n->l)) {
			buffer_free(b);
			return -1;
		}
		
		for (i = post; t->ptr[i] == ' ' || t->ptr[i] == '\t'; i++);
			
		buffer_copy_string_len(b, t->ptr + i, t->used - i - 1);
		if (n->r == NULL) n->r = tnode_init();
		if (-1 == cache_trigger_parse(srv, con, p, b, n->r)) {
			buffer_free(b);
			
			return -1;
		}
		
		buffer_free(b);
	} else {
		char *br_open;
		
		if (t->ptr[0] == '(' && 
		    t->ptr[t->used - 2] == ')') {
			buffer *b;
			b = buffer_init();
			
			buffer_copy_string_len(b, t->ptr + 1, t->used - 3);
			
			if (-1 == cache_trigger_parse(srv, con, p, b, n)) {
				buffer_free(b);
				return -1;
			}
			
			buffer_free(b);
			
			return 0;
		} else if (t->ptr[0] == '"' && 
			   t->ptr[t->used - 2] == '"') {
			/* a string */
			
			tnode_prepare_string(n);
			buffer_copy_string_len(n->value.data.str, t->ptr + 1, t->used - 3);
			
			return 0;
		} else if (NULL != (br_open = strchr(t->ptr, '(')) && 
		    t->ptr[t->used - 2] == ')') {
			/* no basic op, perhaps a function */
			
			for (i = 0; f[i].name; i++) {
				size_t slen;
				
				slen = br_open - t->ptr;
			
				if ((strlen(f[i].name) == slen) && 
				    (0 == strncmp(f[i].name, t->ptr, slen))) {
					/* we know the function */
					
					/* parse parameters */
					
					tnode_val_array_reset(p->params);
					
					if (0 != cache_parse_parameters(srv, con, p, br_open + 1, t->used - slen - 3, p->params)) {
						log_error_write(srv, __FILE__, __LINE__, "s", 
								"parsing parameters failed");
						
						return -1;
					}
					
					if (p->params->used != f[i].params) {
						log_error_write(srv, __FILE__, __LINE__, "sssdsd", 
								"wrong param-count for", f[i].name,
								"got", p->params->used,
								"expected", f[i].params);
						return -1;
					}
					
					
					if (0 != f[i].func(srv, con, p, n)) {
						log_error_write(srv, __FILE__, __LINE__, "ss", 
								"calling function failed for", 
								f[i].name);
						return -1;
					}
					
					return 0;
				}
			}
		} else {
			char *err;
			
			tnode_prepare_long(n);
			VAL_LONG(n) = strtol(t->ptr, &err, 10);
			
			if (*err != '\0') {
				/* isn't a int */
				log_error_write(srv, __FILE__, __LINE__, "sss", 
						"can't evaluate:", 
						t->ptr, err);
				
				return -1;
			}
		}
	}
	
	return 0;
}

int cache_ops_long(tnode *res, tnode *l, tnode *r) {
	if (!IS_LONG(l) || !IS_LONG(r)) {
		return -1;
	}
	
#define OP1(x, y) \
case x: \
	VAL_LONG(res) = (VAL_LONG(l) y VAL_LONG(r)); \
	break;
#define OP2(x, y) \
case x: \
	VAL_LONG(res) = (VAL_LONG(l) y VAL_LONG(r)); \
	break;
	
	switch(res->op) {
		OP1(MINUS, -);
		OP1(PLUS,  +);
		OP1(TIMES, *);
		OP1(PART,  /);
		OP2(GT,    >);
		OP2(LT,    <);
		OP2(EQ,    ==);
		OP2(NE,    !=);
		OP2(LE,    >=);
		OP2(GE,    <=);
		OP2(AND,   &&);
		OP2(OR,    ||);
	default:
		return -1;
	}
#undef OP1
#undef OP2
	
	tnode_prepare_long(res);
	res->value.type = T_NODE_VALUE_LONG;
	res->op = UNSET;
	
	return 0;
}

int cache_ops_string(tnode *res, tnode *l, tnode *r) {
	if (!IS_STRING(l) || !IS_STRING(r)) {
		return -1;
	}
	
	switch(res->op) {
	case PLUS:
		tnode_prepare_string(res);
		
		buffer_copy_string_buffer(VAL_STRING(res), VAL_STRING(l));
		buffer_append_string_buffer(VAL_STRING(res), VAL_STRING(r));
		
		res->value.type = T_NODE_VALUE_STRING;
		res->op = UNSET;
		
		break;
	default:
		return -1;
	}
	
	return 0;
}

int cache_trigger_eval(server *srv, connection *con, plugin_data *p, tnode *t) {
	if (t->op == UNSET) {
		/* a value */
		
		return 0;
	}
	
	if (t->l->op != UNSET) {
		if (-1 == cache_trigger_eval(srv, con, p, t->l)) {
			fprintf(stderr, "%s.%d\n", __FILE__, __LINE__);
			return -1;
		}
	}
	
	if (t->r->op != UNSET) {
		if (-1 == cache_trigger_eval(srv, con, p, t->r)) {
			fprintf(stderr, "%s.%d\n", __FILE__, __LINE__);
			return -1;
		}
	}
	
	/* left and right are simple datatypes now */
	if (IS_LONG(t->l) && IS_LONG(t->r)) {
		if (-1 == cache_ops_long(t, t->l, t->r)) {
			fprintf(stderr, "%s.%d\n", __FILE__, __LINE__);
			return -1;
		}
	} else if (IS_STRING(t->l) && IS_STRING(t->r)) {
		if (-1 == cache_ops_string(t, t->l, t->r)) {
			fprintf(stderr, "%s.%d: cache_ops_string failed\n", __FILE__, __LINE__);
			return -1;
		}
	} else {
		fprintf(stderr, "%s.%d: typemismatch\n",
			__FILE__, __LINE__);
		
		return -1;
	}
	
	return 0;
}

int cache_trigger(server *srv, connection *con, plugin_data *p) {
	size_t i;
	tnode *t;
	
	t = tnode_init();
	for (i = 0; i < p->trigger_if->used; i++) {
		if (-1 == cache_trigger_parse(srv, con, p, p->trigger_if->ptr[i], t)) {
			fprintf(stderr, "%s.%d: cache_trigger_parse failed\n", __FILE__, __LINE__);
			return -1;
		}
		
		if (-1 == cache_trigger_eval(srv, con, p, t)) {
			fprintf(stderr, "%s.%d: cache_trigger_eval failed\n", __FILE__, __LINE__);
			return -1;
		}

		if (IS_LONG(t)) {
#if 0
			fprintf(stderr, "eval: %s = %ld\n", p->trigger_if->ptr[i]->ptr, VAL_LONG(t));
#endif
			if (VAL_LONG(t) != 0) {
				tnode_free(t);
			
				return 1;
			}
		} else if (IS_STRING(t)) {
#if 0
			fprintf(stderr, "eval: %s = '%s'\n", p->trigger_if->ptr[i]->ptr, VAL_STRING(t)->ptr);
#endif
			if (VAL_STRING(t)->used > 1) {
				tnode_free(t);
				
				return 1;
			}
		}
	}
	
	tnode_free(t);
	
	return 0;
}

/**
 * parse the cache-file 
 * 
 * if cache-file is broken, call handler
 * if no handler is set, report 500 
 * 
 * known keywords
 * 
 * - include 
 * - content-type
 * 
 */
int cache_parse(server *srv, connection *con, plugin_data *p, buffer *fn) {
	stream cf;
	char *line, *end;
	int r;
	
	if (0 != stream_open(&cf, fn)) {
		log_error_write(srv, __FILE__, __LINE__, "s", strerror(errno));
		return -1;
	}
	
	buffer_reset(srv->tmp_buf);
	
	for (line = cf.start; 
	     NULL != (end = (memchr(line, '\n', cf.size - (line - cf.start)))) && (end - cf.start < cf.size);
	     line = end + 1) {
		int s_len, key_len;
		char *value;

		s_len = end - line;
		
		if (*line == '#') continue;
		if (s_len == 0) continue;
		
		if (line[s_len-1] == '\\') {
			/* backslash at the end of the line */
			
			buffer_append_string_len(srv->tmp_buf, line, s_len - 1);
			
			continue;
		}
		
		buffer_append_string_len(srv->tmp_buf, line, s_len);
		
		if ((NULL == (value = strchr(srv->tmp_buf->ptr, ' '))) &&
		    (NULL == (value = strchr(srv->tmp_buf->ptr, '\t')))) {
			log_error_write(srv, __FILE__, __LINE__, "sss", fn->ptr, "whitespace is missing: <key> <value>", srv->tmp_buf->ptr);
			
			stream_close(&cf);
			return -1;
		}
		
		key_len = value - srv->tmp_buf->ptr;
		
		/* strip spaces */
		for(; *value == ' '; value++);
		
		switch(key_len) {
		case 4:
			if (0 == strncmp(srv->tmp_buf->ptr, "eval", key_len)) {
				buffer *b;
				
				b = buffer_array_append_get_buffer(p->eval);
				buffer_copy_string(b, value);
			} else {
				log_error_write(srv, __FILE__, __LINE__, "db", key_len, srv->tmp_buf);
			}
			break;
		case 10:
			if (0 == strncmp(srv->tmp_buf->ptr, "trigger.if", key_len)) {
				buffer *b;
				
				b = buffer_array_append_get_buffer(p->trigger_if);
				buffer_copy_string(b, value);
			} else {
				log_error_write(srv, __FILE__, __LINE__, "db", key_len, srv->tmp_buf);
			}
			break;
		case 14:
			if (0 == strncmp(srv->tmp_buf->ptr, "output.include", key_len)) {
				struct stat st;
				buffer *b;
				
				b = buffer_array_append_get_buffer(p->output_include);
				
				buffer_copy_string_buffer(b, p->basedir);
				buffer_append_string(b, value); 
				
				if (-1 == stat(b->ptr, &st)) {
					log_error_write(srv, __FILE__, __LINE__, "sbs", "output.include:", b, strerror(errno));
					
					p->output_include->used--;
					
					stream_close(&cf);
					return -1;
				}
			} else {
				log_error_write(srv, __FILE__, __LINE__, "db", key_len, srv->tmp_buf);
			}
			break;
		case 15:
			if (0 == strncmp(srv->tmp_buf->ptr, "trigger.handler", key_len)) {
				/* 
				 * if one of the trigger.if's is true, the trigger.handler is called
				 * 
				 * the output of the trigger is sent to the client
				 * 
				 */
				
				buffer *b;
				
				b = p->trigger_handler;
				
				buffer_copy_string_buffer(b, p->basedir);
				buffer_append_string(b, value); 
			} else {
				log_error_write(srv, __FILE__, __LINE__, "db", key_len, srv->tmp_buf);
			}
			break;
		case 19:
			if (0 == strncmp(srv->tmp_buf->ptr, "output.content-type", key_len)) {
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), value, strlen(value));
			} else {
				log_error_write(srv, __FILE__, __LINE__, "db", key_len, srv->tmp_buf);
			}
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "db", key_len, srv->tmp_buf);
			break;
		}
		
		buffer_reset(srv->tmp_buf);
	}
	
	stream_close(&cf);
	
	if (p->trigger_handler->used && (0 != (r = cache_trigger(srv, con, p)))) {
		
		if (r == -1) return -1;
		
		/* triggering */
		
		/* rewrite filename */
		buffer_copy_string_buffer(con->physical.path, p->trigger_handler);
		
		chunkqueue_reset(con->write_queue);
		
		return 1;
	} else {
		size_t i;
		struct stat st;
		
		for (i = 0; i < p->output_include->used; i++) {
			buffer *b = p->output_include->ptr[i];
			
			stat(b->ptr, &st);
			
			chunkqueue_append_file(con->write_queue, b, 0, st.st_size);
		}
		
		con->file_finished = 1;
	}
	
	return 0;
}

int cache_parse_parameter(server *srv, connection *con, plugin_data *p, const char *param, size_t param_len, tnode_val *val) {
	buffer *b;
	tnode *t;
	
	b = buffer_init();
				
	buffer_copy_string_len(b, param, param_len);
	
	t = tnode_init();
	
	/* we got an expression */
	if (-1 == cache_trigger_parse(srv, con, p, b, t)) {
		fprintf(stderr, "%s.%d: cache_trigger_parse failed: %s\n", __FILE__, __LINE__, b->ptr);
		return -1;
	}
	
	if (-1 == cache_trigger_eval(srv, con, p, t)) {
		fprintf(stderr, "%s.%d: cache_trigger_eval failed\n", __FILE__, __LINE__);
		return -1;
	}
	
	buffer_free(b);
	
	/* t is our value */
	
	tnode_val_move(val, &(t->value));
	
	tnode_free(t);
	
	return 0;
}


int cache_parse_parameters(server *srv, connection *con, plugin_data *p, const char *params, size_t param_len, tnode_val_array *res) {
	/*
	 * scheme:
	 * <expression>[, <expression>]
	 * 
	 */
	size_t i;
	
	int quotes = 0;
	const char *start;
	tnode_val *tv;
	
	start = params;
	for (i = 0; i < param_len; i++) {
		char c = params[i];
		if (c == '\\' && params[i+1] == '"' && quotes) i++;
		if (c == '"') quotes = quotes ? 0 : 1;
		
		if (!quotes) {
			if (c == ',') {
				tv = tnode_val_init();
				
				if (-1 == cache_parse_parameter(srv, con, p, start, params + (i-1) - start, tv)) {
					fprintf(stderr, "%s.%d: cache_parse_parameter failed: %s\n", __FILE__, __LINE__, start);
					return -1;
				}
				
				tnode_val_array_append(res, tv);
				
				start = params + i + 1;
			}
		}
	}
	
	tv = tnode_val_init();
	
	if (-1 == cache_parse_parameter(srv, con, p, start, params + param_len - start, tv)) {
		fprintf(stderr, "%s.%d: cache_parse_parameter failed: %s\n", __FILE__, __LINE__, start);
		return -1;
	}
	
	tnode_val_array_append(res, tv);
	
	if (quotes != 0) {
		fprintf(stderr, "%s.%d: quotes don't match: %s\n", __FILE__, __LINE__, params);
		return -1;
	}
	
	return 0;
}
