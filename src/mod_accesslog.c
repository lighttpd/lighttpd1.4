#include "first.h"

#include "sys-time.h"

#include "base.h"
#include "fdevent.h"
#include "fdlog.h"
#include "log.h"
#include "buffer.h"
#include "http_header.h"
#include "response.h"
#include "sock_addr.h"

#include "plugin.h"

#include <sys/types.h>
#include <sys/stat.h>
#include "sys-unistd.h" /* <unistd.h> */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

typedef struct {
	char key;
	enum {
			FORMAT_UNSET,
			FORMAT_LITERAL,
			FORMAT_HEADER,
			FORMAT_RESPONSE_HEADER,
			FORMAT_ENV,
			FORMAT_TIMESTAMP,
			FORMAT_TIME_USED,
			FORMAT_REMOTE_ADDR,
			FORMAT_HTTP_HOST,
			FORMAT_REQUEST_LINE,
			FORMAT_STATUS,
			FORMAT_BYTES_OUT_NO_HEADER,
			FORMAT_BYTES_OUT,
			FORMAT_BYTES_IN,
			FORMAT_SERVER_NAME,
			FORMAT_REQUEST_PROTOCOL,
			FORMAT_REQUEST_METHOD,
			FORMAT_COOKIE,

			FORMAT_SERVER_PORT,
			FORMAT_LOCAL_ADDR,
			FORMAT_KEEPALIVE_COUNT,
			FORMAT_URL,
			FORMAT_QUERY_STRING,
			FORMAT_FILENAME,
			FORMAT_CONNECTION_STATUS,
			FORMAT_NOTE,        /* same as FORMAT_ENV */
			FORMAT_REMOTE_HOST, /* same as FORMAT_REMOTE_ADDR */
			FORMAT_REMOTE_USER, /* redirected to FORMAT_ENV */
			FORMAT_TIME_USED_US,/* redirected to FORMAT_TIME_USED */
			/*(parsed and replaced at startup)*/
			FORMAT_REMOTE_IDENT,
			FORMAT_PERCENT,

			FORMAT_UNSUPPORTED
	} tag;
} format_mapping;

/**
 *
 *
 * "%h %V %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
 *
 */

static const format_mapping fmap[] =
{
	{ '%', FORMAT_PERCENT },      /*(parsed and replaced at startup)*/
	{ 'a', FORMAT_REMOTE_ADDR },
	{ 'A', FORMAT_LOCAL_ADDR },
	{ 'b', FORMAT_BYTES_OUT_NO_HEADER },
	{ 'B', FORMAT_BYTES_OUT_NO_HEADER },
	{ 'C', FORMAT_COOKIE },
	{ 'D', FORMAT_TIME_USED_US },
	{ 'e', FORMAT_ENV },
	{ 'f', FORMAT_FILENAME },
	{ 'h', FORMAT_REMOTE_HOST },  /*(parsed and redirected at startup)*/
	{ 'H', FORMAT_REQUEST_PROTOCOL },
	{ 'i', FORMAT_HEADER },
	{ 'I', FORMAT_BYTES_IN },
	{ 'k', FORMAT_KEEPALIVE_COUNT },
	{ 'l', FORMAT_REMOTE_IDENT }, /*(parsed and replaced at startup)*/
	{ 'm', FORMAT_REQUEST_METHOD },
	{ 'n', FORMAT_NOTE },         /*(parsed and redirected at startup)*/
	{ 'o', FORMAT_RESPONSE_HEADER },
	{ 'O', FORMAT_BYTES_OUT },
	{ 'p', FORMAT_SERVER_PORT },
	{ 'P', FORMAT_UNSUPPORTED }, /* we are only one process */
	{ 'q', FORMAT_QUERY_STRING },
	{ 'r', FORMAT_REQUEST_LINE },
	{ 's', FORMAT_STATUS },
	{ 't', FORMAT_TIMESTAMP },
	{ 'T', FORMAT_TIME_USED },
	{ 'u', FORMAT_REMOTE_USER },  /*(parsed and redirected at startup)*/
	{ 'U', FORMAT_URL }, /* w/o querystring */
	{ 'v', FORMAT_SERVER_NAME },
	{ 'V', FORMAT_HTTP_HOST },
	{ 'X', FORMAT_CONNECTION_STATUS },

	{ '\0', FORMAT_UNSET }
};


enum e_optflags_time {
	/* format string is passed to strftime unless other format optflags set
	 * (besides FORMAT_FLAG_TIME_BEGIN or FORMAT_FLAG_TIME_END) */
	FORMAT_FLAG_TIME_END       = 0x00,/* use request end time (default) */
	FORMAT_FLAG_TIME_BEGIN     = 0x01,/* use request start time */
	FORMAT_FLAG_TIME_SEC       = 0x02,/* request time as num  sec since epoch */
	FORMAT_FLAG_TIME_MSEC      = 0x04,/* request time as num msec since epoch */
	FORMAT_FLAG_TIME_USEC      = 0x08,/* request time as num usec since epoch */
	FORMAT_FLAG_TIME_NSEC      = 0x10,/* request time as num nsec since epoch */
	FORMAT_FLAG_TIME_MSEC_FRAC = 0x20,/* request time msec fraction */
	FORMAT_FLAG_TIME_USEC_FRAC = 0x40,/* request time usec fraction */
	FORMAT_FLAG_TIME_NSEC_FRAC = 0x80 /* request time nsec fraction */
};

enum e_optflags_port {
	FORMAT_FLAG_PORT_LOCAL     = 0x01,/* (default) */
	FORMAT_FLAG_PORT_REMOTE    = 0x02
};


typedef struct {
    int field;
    int opt;
    buffer string;
} format_field;

typedef struct {
    unix_time64_t last_generated_accesslog_ts;
    buffer ts_accesslog_str;
  #if defined(__STDC_VERSION__) && __STDC_VERSION__-0 >= 199901L /* C99 */
    format_field ptr[];  /* C99 VLA */
  #else
    format_field ptr[1];
  #endif
} format_fields;

typedef struct {
	fdlog_st *fdlog;
	char use_syslog; /* syslog has global buffer */
	uint8_t escaping;
	unsigned short syslog_level;

	format_fields *parsed_format;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;

    format_fields *default_format;/* allocated if default format */
} plugin_data;

typedef void(esc_fn_t)(buffer * restrict b, const char * restrict s, size_t len);

typedef enum {
    BS_ESCAPE_DEFAULT
   ,BS_ESCAPE_JSON
} buffer_bs_escape_t;

INIT_FUNC(mod_accesslog_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

__attribute_cold__
static format_fields * accesslog_parse_format_err(log_error_st *errh, const char *file, unsigned int line, format_field *f, const char *msg) {
    log_error(errh, file, line, "%s", msg);
    for (; f->field != FORMAT_UNSET; ++f) free(f->string.ptr);
    return NULL;
}

static int accesslog_parse_format_token (const char c) {
    const format_mapping *p = fmap;
    while (p->key != c && p->key != '\0') ++p;
    return p->tag;
}

static format_fields * accesslog_parse_format(const char * const format, const uint32_t flen, log_error_st * const errh) {
    /* common log format (the default) results in 18 elements,
     * so 127 should be enough except for obscene custom usage */
    uint32_t used = 0;
    const uint32_t sz = 127;/* (sz+1 must match fptr[] num elts below) */
    format_field *f;
    format_field fptr[128]; /* (128 elements takes 4k on stack in 64-bit) */
    memset(fptr, 0, sizeof(fptr));
    /*assert(FORMAT_UNSET == 0);*/
    if (0 == flen) return NULL;
    uint32_t i = 0;
    do {
        uint32_t start = i;
        while (format[i] != '%' && ++i < flen) ;
        if (start != i) {
            /* save string from start to i */
            if (used && (f = fptr+used-1)->field == FORMAT_LITERAL)
                buffer_append_string_len(&f->string, format + start, i - start);
            else {
                if (used == sz)
                    return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
                             "too many fields (>= 127) in accesslog.format");

                f = fptr + used++;
                f->field = FORMAT_LITERAL;
                buffer_copy_string_len(&f->string, format + start, i - start);
            }
        }
        if (i == flen) break;

        uint32_t k = ++i; /* step over '%' */
        if (i == flen)
            return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
              "% must be followed by a format-specifier");

        /* we need a new field */
        if (used == sz)
            return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
              "too many fields (>= 127) in accesslog.format");

        /* search for the terminating command */
        if (format[i] == '{') {
            k = ++i;
            while (i < flen && format[i] != '}') ++i;
            if (i == flen || i == k) {
                return accesslog_parse_format_err(errh,__FILE__,__LINE__,fptr,
                  "%{...} must contain string and %{ must be terminated by }");
            }
            ++i;
        }
        else {
            /* skip over (ignore) '<' or '>' */
            if (format[i] == '<' || format[i] == '>') k = ++i;

            /* special-case "%%" and "%l" */
            if (i < flen && (format[i] == '%' || format[i] == 'l')) {
                /* replace "%%" with literal '%' */
                /* replace "%l" with literal '-'; ignore remote ident */
                if (0 == used || (f = fptr+used-1)->field != FORMAT_LITERAL) {
                    f = fptr + used++;
                    f->field = FORMAT_LITERAL;
                }
                buffer_append_char(&f->string, format[i] == '%' ? '%' : '-');
                continue;
            }
        }
        /* add field */
        f = fptr + used++;
        if (i != k) /* %{...} */
            buffer_copy_string_len(&f->string, format + k, i - k - 1);
        f->field = (i < flen)
          ? accesslog_parse_format_token(format[i])
          : FORMAT_UNSET;

        if (f->field == FORMAT_UNSET)
            return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
              "% or %{...} must be followed by a valid format-specifier");
    } while (++i < flen);

    format_fields * const fields =
      ck_malloc(sizeof(format_fields) + ((used+1) * sizeof(format_field)));
    memset(fields, 0, sizeof(format_fields));
    memcpy(fields->ptr, fptr, (used+1) * sizeof(format_field));
    return fields;
}

static void mod_accesslog_free_format_fields(format_fields * const ff) {
    for (format_field *f = ff->ptr; f->field != FORMAT_UNSET; ++f)
        free(f->string.ptr);
    free(ff->ts_accesslog_str.ptr);
    free(ff);
}

FREE_FUNC(mod_accesslog_free) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 0: /* accesslog.filename */
                /*(handled by fdlog_closeall())*/
                break;
              case 1: /* accesslog.format */
                mod_accesslog_free_format_fields(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }

    if (NULL != p->default_format) {
        mod_accesslog_free_format_fields(p->default_format);
    }
}

static void mod_accesslog_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0:{/* accesslog.filename */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->fdlog = cpv->v.v;
        break;
      }
      case 1:{/* accesslog.format */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->parsed_format = cpv->v.v;
        break;
      }
      case 2: /* accesslog.use-syslog */
        pconf->use_syslog = (int)cpv->v.u;
        break;
      case 3: /* accesslog.syslog-level */
        pconf->syslog_level = cpv->v.shrt;
        break;
      case 4: /* accesslog.escaping */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->escaping = (int)cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_accesslog_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_accesslog_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_accesslog_patch_config(request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_accesslog_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static format_fields * mod_accesslog_process_format(const char * const format, const uint32_t flen, server * const srv);

SETDEFAULTS_FUNC(mod_accesslog_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("accesslog.filename"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("accesslog.format"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("accesslog.use-syslog"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("accesslog.syslog-level"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("accesslog.escaping"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_accesslog"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    int uses_syslog = 0;
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        int use_syslog = 0;
        config_plugin_value_t *cpvfile = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* accesslog.filename */
                if (!buffer_is_blank(cpv->v.b))
                    cpvfile = cpv;
                else {
                    cpv->v.v = NULL;
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                break;
              case 1: /* accesslog.format */
                if (NULL != strchr(cpv->v.b->ptr, '\\')) {
                    /* process basic backslash-escapes in format string */
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    char *t = b->ptr;
                    for (char *s = t; *s; ++s) {
                        if (s[0] != '\\') { *t++ = *s; continue; }
                        if (s[1] == '\0') continue; /*(ignore dangling '\\')*/
                        switch (*++s) {
                          case 'a': *t++ = '\a'; break; /* bell */
                          case 'b': *t++ = '\b'; break; /* backspace */
                          case 'f': *t++ = '\f'; break; /* form feed */
                          case 'n': *t++ = '\n'; break; /* newline */
                          case 'r': *t++ = '\r'; break; /* carriage return */
                          case 't': *t++ = '\t'; break; /* horizontal tab */
                          case 'v': *t++ = '\v'; break; /* vertical tab */
                          /*case '"':*/
                          /*case '\\':*/
                          default:  *t++ = *s;   break; /*(use literal char)*/
                        }
                    }
                    buffer_truncate(b, (size_t)(t - b->ptr));
                }
                cpv->v.v =
                  mod_accesslog_process_format(BUF_PTR_LEN(cpv->v.b), srv);
                if (NULL == cpv->v.v) return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 2: /* accesslog.use-syslog */
                use_syslog = (int)cpv->v.u;
                break;
              case 3: /* accesslog.syslog-level */
                break;
              case 4: /* accesslog.escaping */
                /* quick parse: 0 == "default", 1 == "json" */
                cpv->v.u = (0 == strcmp(cpv->v.b->ptr, "json"))
                  ? BS_ESCAPE_JSON
                  : BS_ESCAPE_DEFAULT;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              default:/* should not happen */
                break;
            }
        }

        if (srv->srvconf.preflight_check) continue;

        uses_syslog |= use_syslog;
        if (use_syslog) continue; /* ignore the next checks */
        cpv = cpvfile; /* accesslog.filename handled after preflight_check */
        if (NULL == cpv) continue;
        const char * const fn = cpv->v.b->ptr;
        cpv->v.v = fdlog_open(fn);
        cpv->vtype = T_CONFIG_LOCAL;
        if (NULL == cpv->v.v) {
            log_perror(srv->errh, __FILE__, __LINE__,
              "opening log '%s' failed", fn);
            return HANDLER_ERROR;
        }
    }

  #ifdef HAVE_SYSLOG_H
    p->defaults.syslog_level = LOG_INFO;
    if (uses_syslog)
        fdlog_openlog(srv->errh, srv->srvconf.syslog_facility);
  #else
    UNUSED(uses_syslog);
  #endif

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_accesslog_merge_config(&p->defaults, cpv);
    }

    if (NULL == p->defaults.parsed_format) {
        /* (set default format even if p->use_syslog since
         *  some other condition might enable logfile) */
        static const char fmt[] =
          "%h %V %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"";
        p->defaults.parsed_format = p->default_format =
          mod_accesslog_process_format(CONST_STR_LEN(fmt), srv);
        if (NULL == p->default_format) return HANDLER_ERROR;
    }

    return HANDLER_GO_ON;
}

static format_fields * mod_accesslog_process_format(const char * const format, const uint32_t flen, server * const srv) {
			format_fields * const parsed_format =
			  accesslog_parse_format(format, flen, srv->errh);
			if (NULL == parsed_format) {
				log_error(srv->errh, __FILE__, __LINE__,
					"parsing accesslog-definition failed: %s", format);
				return NULL;
			}

			uint32_t tcount = 0;
			for (format_field *f = parsed_format->ptr; f->field != FORMAT_UNSET; ++f) {
				buffer * const fstr = &f->string;
				if (FORMAT_LITERAL == f->field) continue;
				if (FORMAT_TIMESTAMP == f->field) {
					if (!buffer_is_blank(fstr)) {
						const char * const ptr = fstr->ptr;
						uint32_t len = buffer_clen(fstr);
						if (0 == strncmp(ptr, "begin:", sizeof("begin:")-1)) {
							f->opt |= FORMAT_FLAG_TIME_BEGIN;
							memmove(fstr->ptr, fstr->ptr+6, len-6); /*"begin:"*/
							buffer_truncate(fstr, len-6);
						} else if (0 == strncmp(ptr, "end:", sizeof("end:")-1)) {
							f->opt |= FORMAT_FLAG_TIME_END;
							memmove(fstr->ptr, fstr->ptr+4, len-4); /*"end:"*/
							buffer_truncate(fstr, len-4);
						}
						if      (0 == strcmp(ptr, "sec"))       f->opt |= FORMAT_FLAG_TIME_SEC;
						else if (0 == strcmp(ptr, "msec"))      f->opt |= FORMAT_FLAG_TIME_MSEC;
						else if (0 == strcmp(ptr, "usec"))      f->opt |= FORMAT_FLAG_TIME_USEC;
						else if (0 == strcmp(ptr, "nsec"))      f->opt |= FORMAT_FLAG_TIME_NSEC;
						else if (0 == strcmp(ptr, "msec_frac")) f->opt |= FORMAT_FLAG_TIME_MSEC_FRAC;
						else if (0 == strcmp(ptr, "usec_frac")) f->opt |= FORMAT_FLAG_TIME_USEC_FRAC;
						else if (0 == strcmp(ptr, "nsec_frac")) f->opt |= FORMAT_FLAG_TIME_NSEC_FRAC;
						else if (NULL == strchr(ptr, '%')) {
							log_error(srv->errh, __FILE__, __LINE__,
								"constant string for time format (misspelled token? or missing '%%'): %s", format);
							mod_accesslog_free_format_fields(parsed_format);
							return NULL;
						}
					}

					/* make sure they didn't try to send the timestamp in twice
					 * (would invalidate pconf->parsed_format.ts_accesslog_str cache of timestamp str) */
					if (!(f->opt & ~(FORMAT_FLAG_TIME_BEGIN|FORMAT_FLAG_TIME_END|FORMAT_FLAG_TIME_SEC)) && ++tcount > 1) {
						log_error(srv->errh, __FILE__, __LINE__,
							"you may not use strftime timestamp format %%{}t twice in the same access log: %s", format);
						mod_accesslog_free_format_fields(parsed_format);
						return NULL;
					}

					if (f->opt & FORMAT_FLAG_TIME_BEGIN) srv->srvconf.high_precision_timestamps = 1;
				} else if (FORMAT_TIME_USED_US == f->field) {
					f->opt |= FORMAT_FLAG_TIME_USEC;
					f->field = FORMAT_TIME_USED;
					srv->srvconf.high_precision_timestamps = 1;
				} else if (FORMAT_TIME_USED == f->field) {
					const char * const ptr = fstr->ptr;
					if (buffer_is_blank(fstr)
					      || 0 == strcmp(ptr, "s")
					      || 0 == strcmp(ptr, "sec"))  f->opt |= FORMAT_FLAG_TIME_SEC;
					else if (0 == strcmp(ptr, "ms")
					      || 0 == strcmp(ptr, "msec")) f->opt |= FORMAT_FLAG_TIME_MSEC;
					else if (0 == strcmp(ptr, "us")
					      || 0 == strcmp(ptr, "usec")) f->opt |= FORMAT_FLAG_TIME_USEC;
					else if (0 == strcmp(ptr, "ns")
					      || 0 == strcmp(ptr, "nsec")) f->opt |= FORMAT_FLAG_TIME_NSEC;
					else {
						log_error(srv->errh, __FILE__, __LINE__,
							"invalid time unit in %%{UNIT}T: %s", format);
						mod_accesslog_free_format_fields(parsed_format);
						return NULL;
					}

					if (f->opt & ~(FORMAT_FLAG_TIME_SEC)) srv->srvconf.high_precision_timestamps = 1;
				} else if (FORMAT_COOKIE == f->field) {
					if (buffer_is_blank(fstr)) f->field = FORMAT_LITERAL; /*(blank)*/
				} else if (FORMAT_SERVER_PORT == f->field) {
					const char * const ptr = fstr->ptr;
					if (buffer_is_blank(fstr))
						f->opt |= FORMAT_FLAG_PORT_LOCAL;
					else if (0 == strcmp(ptr, "canonical"))
						f->opt |= FORMAT_FLAG_PORT_LOCAL;
					else if (0 == strcmp(ptr, "local"))
						f->opt |= FORMAT_FLAG_PORT_LOCAL;
					else if (0 == strcmp(ptr, "remote"))
						f->opt |= FORMAT_FLAG_PORT_REMOTE;
					else {
						log_error(srv->errh, __FILE__, __LINE__,
							"invalid format %%{canonical,local,remote}p: %s", format);
						mod_accesslog_free_format_fields(parsed_format);
						return NULL;
					}
				} else if (FORMAT_HEADER == f->field
				           || FORMAT_RESPONSE_HEADER == f->field) {
					if (buffer_is_blank(fstr)) f->field = FORMAT_LITERAL; /*(blank)*/
					else f->opt = http_header_hkey_get(BUF_PTR_LEN(fstr));
				} else if (FORMAT_REMOTE_HOST == f->field
				           || FORMAT_REMOTE_ADDR == f->field) {
					f->field = FORMAT_REMOTE_ADDR;
					const char * const ptr = fstr->ptr;
					if (buffer_is_blank(fstr)) {
					}
					else if (0 == strcmp(ptr, "mask"))
						f->opt = 1; /* mask IP addr lower bits (partial anon) */
					else {
						log_error(srv->errh, __FILE__, __LINE__,
							"invalid format %%{mask}a: %s", format);
						mod_accesslog_free_format_fields(parsed_format);
						return NULL;
					}
				} else if (FORMAT_REMOTE_USER == f->field) {
					f->field = FORMAT_ENV;
					buffer_copy_string_len(fstr, CONST_STR_LEN("REMOTE_USER"));
				} else if (FORMAT_ENV == f->field
				           || FORMAT_NOTE == f->field) {
					if (buffer_is_blank(fstr)) f->field = FORMAT_LITERAL; /*(blank)*/
					else f->field = FORMAT_ENV;
				}
			}

			return parsed_format;
}

TRIGGER_FUNC(log_access_periodic_flush) {
    UNUSED(p_d);
    /* flush buffered access logs every 4 seconds */
    if (0 == (log_monotonic_secs & 3)) fdlog_files_flush(srv->errh, 0);
    return HANDLER_GO_ON;
}

static void
accesslog_append_buffer (buffer * const restrict dest,
                         const buffer * const restrict b, esc_fn_t esc_fn)
{
    if (!buffer_string_is_empty(b))
        esc_fn(dest, BUF_PTR_LEN(b));
    else
        buffer_append_char(dest, '-');
}

static void
accesslog_append_bytes (buffer * const dest, off_t bytes, const uint32_t adj)
{
    if (bytes > 0)
        buffer_append_int(dest, (bytes -= (off_t)adj) > 0 ? bytes : 0);
    else
        buffer_append_char(dest, '-');
}

__attribute_cold__
__attribute_noinline__
static void
accesslog_append_cookie (buffer * const restrict dest,
                         const request_st * const restrict r,
                         const buffer * const restrict name,
                         esc_fn_t esc_fn)
{
    const buffer * const vb =
      http_header_request_get(r, HTTP_HEADER_COOKIE, CONST_STR_LEN("Cookie"));
    if (NULL == vb) return;

    char *str = vb->ptr;
    size_t len = buffer_clen(name);
    do {
        while (*str == ' ' || *str == '\t') ++str;
        if (0 == strncmp(str, name->ptr, len) && str[len] == '=') {
            char *v = str+len+1;
            for (str = v; *str != '\0' && *str != ';'; ++str) ;
            if (str == v) break;
            do { --str; } while (str > v && (*str == ' ' || *str == '\t'));
            esc_fn(dest, v, str - v + 1);
            break;
        }
        else {
            while (*str != ';' && *str != ' ' && *str != '\t' && *str != '\0')
                ++str;
        }
        while (*str == ' ' || *str == '\t') ++str;
    } while (*str++ == ';');
}

static int
accesslog_append_time (buffer * const b, const request_st * const r,
                       const format_field * const f,
                       unix_timespec64_t * const ts,
                       format_fields * const parsed_format)
{
			int flush = 0;
			if (f->field == FORMAT_TIMESTAMP) {
				if (f->opt & ~(FORMAT_FLAG_TIME_BEGIN|FORMAT_FLAG_TIME_END)) {
					if (f->opt & FORMAT_FLAG_TIME_SEC) {
						unix_time64_t t = (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) ? log_epoch_secs : r->start_hp.tv_sec;
						buffer_append_int(b, (intmax_t)t);
					} else if (f->opt & (FORMAT_FLAG_TIME_MSEC|FORMAT_FLAG_TIME_USEC|FORMAT_FLAG_TIME_NSEC)) {
						unix_time64_t t;
						long ns;
						if (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) {
							if (0 == ts->tv_sec) log_clock_gettime_realtime(ts);
							t = ts->tv_sec;
							ns = ts->tv_nsec;
						} else {
							t = r->start_hp.tv_sec;
							ns = r->start_hp.tv_nsec;
						}
						if (f->opt & FORMAT_FLAG_TIME_MSEC) {
							t *= 1000;
							t += (ns + 999999) / 1000000; /* ceil */
						} else if (f->opt & FORMAT_FLAG_TIME_USEC) {
							t *= 1000000;
							t += (ns + 999) / 1000; /* ceil */
						} else {/*(f->opt & FORMAT_FLAG_TIME_NSEC)*/
							t *= 1000000000;
							t += ns;
						}
						buffer_append_int(b, (intmax_t)t);
					} else { /*(FORMAT_FLAG_TIME_MSEC_FRAC|FORMAT_FLAG_TIME_USEC_FRAC|FORMAT_FLAG_TIME_NSEC_FRAC)*/
						long ns;
						char *ptr;
						if (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) {
							if (0 == ts->tv_sec) log_clock_gettime_realtime(ts);
							ns = ts->tv_nsec;
						} else {
							ns = r->start_hp.tv_nsec;
						}
						/*assert(t < 1000000000);*/
						if (f->opt & FORMAT_FLAG_TIME_MSEC_FRAC) {
							ns +=  999999; /* ceil */
							ns /= 1000000;
							buffer_append_string_len(b, CONST_STR_LEN("000"));
						} else if (f->opt & FORMAT_FLAG_TIME_USEC_FRAC) {
							ns +=  999; /* ceil */
							ns /= 1000;
							buffer_append_string_len(b, CONST_STR_LEN("000000"));
						} else {/*(f->opt & FORMAT_FLAG_TIME_NSEC_FRAC)*/
							buffer_append_string_len(b, CONST_STR_LEN("000000000"));
						}
						ptr = b->ptr + buffer_clen(b);
						for (long x; ns > 0; ns = x)
							*--ptr += (ns - (x = ns/10) * 10); /* ns % 10 */
					}
				} else {
					buffer * const ts_accesslog_str = &parsed_format->ts_accesslog_str;
					/* cache the generated timestamp (only if ! FORMAT_FLAG_TIME_BEGIN) */
					unix_time64_t t;
					struct tm tm;

					if (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) {
						const unix_time64_t cur_ts = log_epoch_secs;
						if (parsed_format->last_generated_accesslog_ts == cur_ts) {
							buffer_append_string_buffer(b, ts_accesslog_str);
							return 0; /* flush == 0 */
						}
						t = parsed_format->last_generated_accesslog_ts = cur_ts;
						flush = 1;
					} else {
						t = r->start_hp.tv_sec;
					}

					const char *fmt = buffer_is_blank(&f->string)
					  ? NULL
					  : f->string.ptr;
					buffer_clear(ts_accesslog_str);
				      #if defined(HAVE_STRUCT_TM_GMTOFF)
					buffer_append_strftime(ts_accesslog_str,
					                     #ifdef __MINGW32__
					                       fmt ? fmt : "[%d/%b/%Y:%H:%M:%S %z]",
					                     #else
					                       fmt ? fmt : "[%d/%b/%Y:%T %z]",
					                     #endif
					                       localtime64_r(&t, &tm));
				      #else /* HAVE_STRUCT_TM_GMTOFF */
					buffer_append_strftime(ts_accesslog_str,
					                     #ifdef ___MINGW32__
					                       fmt ? fmt : "[%d/%b/%Y:%H:%M:%S +0000]",
					                     #else
					                       fmt ? fmt : "[%d/%b/%Y:%T +0000]",
					                     #endif
					                       gmtime64_r(&t, &tm));
				      #endif /* HAVE_STRUCT_TM_GMTOFF */
					buffer_append_string_buffer(b, ts_accesslog_str);
				}
			}
			else { /* FORMAT_TIME_USED or FORMAT_TIME_USED_US */
				if (f->opt & FORMAT_FLAG_TIME_SEC) {
					buffer_append_int(b, log_epoch_secs - r->start_hp.tv_sec);
				} else {
					const unix_timespec64_t * const bs = &r->start_hp;
					off_t tdiff; /*(expected to be 64-bit since large file support enabled)*/
					if (0 == ts->tv_sec) log_clock_gettime_realtime(ts);
					tdiff = (off_t)(ts->tv_sec - bs->tv_sec)*1000000000 + (ts->tv_nsec - bs->tv_nsec);
					if (tdiff <= 0) {
						/* sanity check for time moving backwards
						 * (daylight savings adjustment or leap seconds or ?) */
						tdiff  = -1;
					} else if (f->opt & FORMAT_FLAG_TIME_MSEC) {
						tdiff +=  999999; /* ceil */
						tdiff /= 1000000;
					} else if (f->opt & FORMAT_FLAG_TIME_USEC) {
						tdiff +=  999; /* ceil */
						tdiff /= 1000;
					} /* else (f->opt & FORMAT_FLAG_TIME_NSEC) */
					buffer_append_int(b, (intmax_t)tdiff);
				}
			}
			return flush;
}

__attribute_noinline__
static void
accesslog_append_remote_addr_masked (buffer * const b, const request_st * const r)
{
    /* mask lower bits of IP address string for logging
     * (similar to masking policy applied by Google Analytics
     *  https://support.google.com/analytics/answer/2763052) */
    /* r->dst_addr_buf is normalized and valid string; operate on known valid */
    const char * const s = r->dst_addr_buf->ptr;
    uint32_t i = 0;
    switch (sock_addr_get_family(r->dst_addr)) {
     #ifdef HAVE_IPV6
      case AF_INET6:
        if (__builtin_expect( (s[0] != ':'), 1)
            || !IN6_IS_ADDR_V4MAPPED(&((sock_addr*)r->dst_addr)->ipv6.sin6_addr)
            || NULL == strchr(s, '.')) {
            /* IPv6: mask final 10 octets (80 bits) of address; keep 6 octets */
            /* Note: treat string starting w/ "::..." as "::" even if "::x:..."
             * (rather than special-casing; does not detect "::x:..." besides
             *  v4mapped "::ffff:1.2.3.4" condition check above) */
            for (int j=0; s[i] != ':' || ((j+=2) != 6 && s[i+1] != ':'); ++i) ;
            buffer_append_str2(b, s, i+1, CONST_STR_LEN(":"));
            break;
        }
        /* IN6_IS_ADDR_V4MAPPED() */
        __attribute_fallthrough__
     #endif
      case AF_INET:
        /* IPv4: mask final octet (8 bits) of address */
       #ifdef __COVERITY__
        force_assert(buffer_clen(r->dst_addr_buf) > 2);
        force_assert(strchr(s, '.') != NULL);
       #endif
        for (i = buffer_clen(r->dst_addr_buf)-1; s[--i] != '.'; ) ;
        buffer_append_str2(b, s, i+1, CONST_STR_LEN("0"));
        break;
      default:
        buffer_append_buffer(b, r->dst_addr_buf);
        break;
    }
}

__attribute_cold__
__attribute_noinline__
static void
log_access_record_cold (buffer * const b, const request_st * const r,
                        const format_field * const f, esc_fn_t esc_fn)
{
    connection * const con = r->con;
    switch (f->field) {
      case FORMAT_SERVER_PORT:
        if (f->opt & FORMAT_FLAG_PORT_REMOTE) {
            buffer_append_int(b, sock_addr_get_port(r->dst_addr));
            break;
        }
        /* else if (f->opt & FORMAT_FLAG_PORT_LOCAL) *//*(default)*/
        __attribute_fallthrough__
      case FORMAT_LOCAL_ADDR:
        {
            const server_socket * const srv_sock = con->srv_socket;
            const buffer * const srv_token = srv_sock->srv_token;
            const uint32_t colon = srv_sock->srv_token_colon;
            if (f->field == FORMAT_LOCAL_ADDR)
                /* (perf: not using getsockname() and
                 *  sock_addr_cache_inet_ntop_copy_buffer())
                 * (still useful if admin has configured explicit listen IPs) */
                buffer_append_string_len(b, srv_token->ptr, colon);
            else { /* FORMAT_SERVER_PORT */
                const uint32_t tlen = buffer_clen(srv_token);
                if (colon < tlen) /*(colon != tlen)*/
                    buffer_append_string_len(b, srv_token->ptr+colon+1,
                                             tlen - (colon+1));
            }
        }
        break;
      case FORMAT_KEEPALIVE_COUNT:
        if (con->request_count > 1)
            buffer_append_int(b, (intmax_t)(con->request_count-1));
        else
            buffer_append_char(b, '0');
        break;
      case FORMAT_URL:
        {
            const uint32_t len = buffer_clen(&r->target);
            const char * const qmark = memchr(r->target.ptr, '?', len);
            esc_fn(b, r->target.ptr,
                   qmark ? (uint32_t)(qmark - r->target.ptr) : len);
        }
        break;
      case FORMAT_QUERY_STRING:
        esc_fn(b, BUF_PTR_LEN(&r->uri.query));
        break;
      case FORMAT_FILENAME:
        accesslog_append_buffer(b, &r->physical.path, esc_fn);
        break;
      case FORMAT_CONNECTION_STATUS:
        buffer_append_char(b, (r->state == CON_STATE_RESPONSE_END)
                              ? r->keep_alive <= 0 ? '-' : '+'
                              : 'X'); /* CON_STATE_ERROR */
        break;
     #if 0 /*(parsed and replaced at startup)*/
      case FORMAT_REMOTE_IDENT:
        /* ident */
        buffer_append_char(b, '-');
        break;
     #endif
     #if 0 /*(parsed and replaced at startup)*/
      case FORMAT_PERCENT:
        buffer_append_char(b, '%');
        break;
     #endif
      default:
        break;
    }
}

static int log_access_record (const request_st * const r, buffer * const b, format_fields * const parsed_format, esc_fn_t esc) {
	const buffer *vb;
	unix_timespec64_t ts = { 0, 0 };
	int flush = 0;

	for (const format_field *f = parsed_format->ptr; f->field != FORMAT_UNSET; ++f) {
			switch(f->field) {
			case FORMAT_LITERAL:
				buffer_append_string_buffer(b, &f->string);
				break;
			case FORMAT_HEADER:
				vb = http_header_request_get(r, f->opt, BUF_PTR_LEN(&f->string));
				accesslog_append_buffer(b, vb, esc);
				break;
			case FORMAT_RESPONSE_HEADER:
				vb = http_header_response_get(r, f->opt, BUF_PTR_LEN(&f->string));
				accesslog_append_buffer(b, vb, esc);
				break;
		  #if 0 /*(parsed and redirected at startup to FORMAT_ENV "REMOTE_USER")*/
			case FORMAT_REMOTE_USER:
				vb = http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
				accesslog_append_buffer(b, vb, esc);
				break;
		  #endif
		  #if 0 /*(parsed and redirected at startup to FORMAT_ENV)*/
			/*case FORMAT_NOTE:*/
		  #endif
			case FORMAT_ENV:
				vb = http_header_env_get(r, BUF_PTR_LEN(&f->string));
				accesslog_append_buffer(b, vb, esc);
				break;
			case FORMAT_TIMESTAMP:
		  #if 0 /*(parsed and redirected at startup to FORMAT_TIME_USED)*/
			case FORMAT_TIME_USED_US:
		  #endif
			case FORMAT_TIME_USED:
				flush |= accesslog_append_time(b, r, f, &ts, parsed_format);
				break;
		  #if 0 /*(parsed and redirected at startup to FORMAT_REMOTE_ADDR)*/
			/*case FORMAT_REMOTE_HOST:*/
		  #endif
			case FORMAT_REMOTE_ADDR:
				if (!f->opt)
					buffer_append_string_buffer(b, r->dst_addr_buf);
				else
					accesslog_append_remote_addr_masked(b, r);
				break;
			case FORMAT_HTTP_HOST:
				accesslog_append_buffer(b, &r->uri.authority, esc);
				break;
			case FORMAT_REQUEST_LINE:
				/*(attempt to reconstruct request line)*/
				http_method_append(b, r->http_method);
				buffer_append_char(b, ' ');
				esc(b, BUF_PTR_LEN(&r->target_orig));
				buffer_append_char(b, ' ');
				http_version_append(b, r->http_version);
				break;
			case FORMAT_STATUS:
				buffer_append_int(b, r->http_status);
				break;
			case FORMAT_BYTES_OUT_NO_HEADER:
				accesslog_append_bytes(b, http_request_stats_bytes_out(r),
				                       r->resp_header_len);
				break;
			case FORMAT_BYTES_OUT:
				accesslog_append_bytes(b, http_request_stats_bytes_out(r), 0);
				break;
			case FORMAT_BYTES_IN:
				accesslog_append_bytes(b, http_request_stats_bytes_in(r), 0);
				break;
			case FORMAT_SERVER_NAME:
				accesslog_append_buffer(b, r->server_name, esc);
				break;
			case FORMAT_REQUEST_PROTOCOL:
				http_version_append(b, r->http_version);
				break;
			case FORMAT_REQUEST_METHOD:
				http_method_append(b, r->http_method);
				break;
			case FORMAT_COOKIE:
				accesslog_append_cookie(b, r, &f->string, esc);
				break;
			default:
				log_access_record_cold(b, r, f, esc);
				break;
			}
	}

	return flush;
}

REQUESTDONE_FUNC(log_access_write) {
    plugin_config pconf;
    mod_accesslog_patch_config(r, p_d, &pconf);
    fdlog_st * const fdlog = pconf.fdlog;

    /* No output device, nothing to do */
    if (!pconf.use_syslog && !fdlog) return HANDLER_GO_ON;

    buffer * const b = (pconf.use_syslog || fdlog->mode == FDLOG_PIPE)
      ? (buffer_clear(r->tmp_buf), r->tmp_buf)
      : &fdlog->b;

    esc_fn_t * const esc_fn = !pconf.escaping
      ? buffer_append_bs_escaped
      : buffer_append_bs_escaped_json;
    const int flush =
      log_access_record(r, b, pconf.parsed_format, esc_fn);

  #ifdef HAVE_SYSLOG_H
    if (pconf.use_syslog) {
        if (!buffer_is_blank(b))
            syslog(pconf.syslog_level, "%s", b->ptr);
        return HANDLER_GO_ON;
    }
  #endif

    buffer_append_char(b, '\n');

    if (flush || fdlog->mode == FDLOG_PIPE || buffer_clen(b) >= 8192) {
        const ssize_t wr = write_all(fdlog->fd, BUF_PTR_LEN(b));
        buffer_clear(b); /*(clear buffer, even on error)*/
        if (-1 == wr)
            log_perror(r->conf.errh, __FILE__, __LINE__,
              "error flushing log %s", fdlog->fn);
    }

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_accesslog_plugin_init(plugin *p);
int mod_accesslog_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "accesslog";

	p->init        = mod_accesslog_init;
	p->set_defaults= mod_accesslog_set_defaults;
	p->cleanup     = mod_accesslog_free;

	p->handle_request_done  = log_access_write;
	p->handle_trigger       = log_access_periodic_flush;

	return 0;
}
