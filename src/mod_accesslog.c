#include "first.h"

#include "sys-time.h"

#include "base.h"
#include "fdevent.h"
#include "fdlog.h"
#include "log.h"
#include "buffer.h"
#include "http_header.h"
#include "sock_addr.h"

#include "plugin.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

typedef struct {
	char key;
	enum {
		FORMAT_UNSET,
			FORMAT_UNSUPPORTED,
			FORMAT_PERCENT,
			FORMAT_REMOTE_HOST,
			FORMAT_REMOTE_IDENT,
			FORMAT_REMOTE_USER,
			FORMAT_TIMESTAMP,
			FORMAT_REQUEST_LINE,
			FORMAT_STATUS,
			FORMAT_BYTES_OUT_NO_HEADER,
			FORMAT_HEADER,

			FORMAT_REMOTE_ADDR,
			FORMAT_LOCAL_ADDR,
			FORMAT_COOKIE,
			FORMAT_TIME_USED_US,
			FORMAT_ENV,
			FORMAT_FILENAME,
			FORMAT_REQUEST_PROTOCOL,
			FORMAT_REQUEST_METHOD,
			FORMAT_SERVER_PORT,
			FORMAT_QUERY_STRING,
			FORMAT_TIME_USED,
			FORMAT_URL,
			FORMAT_SERVER_NAME,
			FORMAT_HTTP_HOST,
			FORMAT_CONNECTION_STATUS,
			FORMAT_BYTES_IN,
			FORMAT_BYTES_OUT,

			FORMAT_KEEPALIVE_COUNT,
			FORMAT_RESPONSE_HEADER,
			FORMAT_NOTE
	} type;
} format_mapping;

/**
 *
 *
 * "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
 *
 */

static const format_mapping fmap[] =
{
	{ '%', FORMAT_PERCENT },
	{ 'h', FORMAT_REMOTE_HOST },
	{ 'l', FORMAT_REMOTE_IDENT },
	{ 'u', FORMAT_REMOTE_USER },
	{ 't', FORMAT_TIMESTAMP },
	{ 'r', FORMAT_REQUEST_LINE },
	{ 's', FORMAT_STATUS },
	{ 'b', FORMAT_BYTES_OUT_NO_HEADER },
	{ 'i', FORMAT_HEADER },

	{ 'a', FORMAT_REMOTE_ADDR },
	{ 'A', FORMAT_LOCAL_ADDR },
	{ 'B', FORMAT_BYTES_OUT_NO_HEADER },
	{ 'C', FORMAT_COOKIE },
	{ 'D', FORMAT_TIME_USED_US },
	{ 'e', FORMAT_ENV },
	{ 'f', FORMAT_FILENAME },
	{ 'H', FORMAT_REQUEST_PROTOCOL },
	{ 'k', FORMAT_KEEPALIVE_COUNT },
	{ 'm', FORMAT_REQUEST_METHOD },
	{ 'n', FORMAT_NOTE },
	{ 'p', FORMAT_SERVER_PORT },
	{ 'P', FORMAT_UNSUPPORTED }, /* we are only one process */
	{ 'q', FORMAT_QUERY_STRING },
	{ 'T', FORMAT_TIME_USED },
	{ 'U', FORMAT_URL }, /* w/o querystring */
	{ 'v', FORMAT_SERVER_NAME },
	{ 'V', FORMAT_HTTP_HOST },
	{ 'X', FORMAT_CONNECTION_STATUS },
	{ 'I', FORMAT_BYTES_IN },
	{ 'O', FORMAT_BYTES_OUT },

	{ 'o', FORMAT_RESPONSE_HEADER },

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
    enum { FIELD_UNSET, FIELD_STRING, FIELD_FORMAT } type;
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
	unsigned short syslog_level;

	format_fields *parsed_format;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    format_fields *default_format;/* allocated if default format */
} plugin_data;

INIT_FUNC(mod_accesslog_init) {
    return calloc(1, sizeof(plugin_data));
}

static void accesslog_append_escaped_str(buffer * const dest, const char * const str, const size_t len) {
	const char *ptr, *start, *end;

	/* replaces non-printable chars with \xHH where HH is the hex representation of the byte */
	/* exceptions: " => \", \ => \\, whitespace chars => \n \t etc. */
	if (0 == len) return;
	buffer_string_prepare_append(dest, len);

	for (ptr = start = str, end = str+len; ptr < end; ++ptr) {
		unsigned char const c = *(const unsigned char *)ptr;
		if (c >= ' ' && c <= '~' && c != '"' && c != '\\') {
			/* nothing to change, add later as one block */
		} else {
			/* copy previous part */
			if (start < ptr) {
				buffer_append_string_len(dest, start, ptr - start);
			}
			start = ptr + 1;

			const char *h2;
			switch (c) {
			case '"':  h2 = "\\\""; break;
			case '\\': h2 = "\\\\"; break;
			case '\b': h2 = "\\b";  break;
			case '\n': h2 = "\\n";  break;
			case '\r': h2 = "\\r";  break;
			case '\t': h2 = "\\t";  break;
			case '\v': h2 = "\\v";  break;
			default: {
					/* non printable char => \xHH */
					char hh[5] = {'\\','x',0,0,0};
					char h = c >> 4;
					hh[2] = (h > 9) ? (h - 10 + 'A') : (h + '0');
					h = c & 0xFF;
					hh[3] = (h > 9) ? (h - 10 + 'A') : (h + '0');
					buffer_append_string_len(dest, hh, 4);
					continue;
				}
			}
			buffer_append_string_len(dest, h2, 2);
		}
	}

	if (start < end) {
		buffer_append_string_len(dest, start, end - start);
	}
}

static void accesslog_append_escaped(buffer *dest, const buffer *str) {
	accesslog_append_escaped_str(dest, BUF_PTR_LEN(str));
}

__attribute_cold__
static format_fields * accesslog_parse_format_err(log_error_st *errh, const char *file, unsigned int line, format_field *f, const char *msg) {
    log_error(errh, file, line, "%s", msg);
    for (; f->type != FIELD_UNSET; ++f) free(f->string.ptr);
    return NULL;
}

static format_fields * accesslog_parse_format(const char * const format, const size_t flen, log_error_st * const errh) {
	/* common log format (the default) results in 18 elements,
	 * so 127 should be enough except for obscene custom usage */
	size_t i, j, k = 0, start = 0;
	uint32_t used = 0;
	const uint32_t sz = 127;/* (sz+1 must match fptr[] num elts below) */
	format_field *f;
	format_field fptr[128]; /* (128 elements takes 4k on stack in 64-bit) */
	memset(fptr, 0, sizeof(fptr));
	if (0 != FIELD_UNSET) return NULL;

	if (0 == flen) return NULL;

	for (i = 0; i < flen; ++i) {
		if (format[i] != '%') continue;

			if (i > 0 && start != i) {
				/* copy the string before this % */
				if (used == sz)
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "too many fields (>= 127) in accesslog.format");

				f = fptr+used;
				f->type = FIELD_STRING;
				memset(&f->string, 0, sizeof(buffer));
				buffer_copy_string_len(&f->string, format + start, i - start);

				++used;
			}

			/* we need a new field */
			if (used == sz)
				return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
				         "too many fields (>= 127) in accesslog.format");

			/* search for the terminating command */
			switch (format[i+1]) {
			case '>':
			case '<':
				/* after the } has to be a character */
				if (format[i+2] == '\0') {
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "%< and %> have to be followed by a format-specifier");
				}


				for (j = 0; fmap[j].key != '\0'; j++) {
					if (fmap[j].key != format[i+2]) continue;

					/* found key */

					f = fptr+used;
					f->type = FIELD_FORMAT;
					f->field = fmap[j].type;
					f->opt = 0;
					f->string.ptr = NULL;

					++used;

					break;
				}

				if (fmap[j].key == '\0') {
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "%< and %> have to be followed by a valid format-specifier");
				}

				start = i + 3;
				i = start - 1; /* skip the string */

				break;
			case '{':
				/* go forward to } */

				for (k = i+2; k < flen; ++k) {
					if (format[k] == '}') break;
				}

				if (k == flen) {
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "%{ has to be terminated by a }");
				}

				/* after the } has to be a character */
				if (format[k+1] == '\0') {
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "%{...} has to be followed by a format-specifier");
				}

				if (k == i + 2) {
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "%{...} has to contain a string");
				}

				for (j = 0; fmap[j].key != '\0'; j++) {
					if (fmap[j].key != format[k+1]) continue;

					/* found key */

					f = fptr+used;
					f->type = FIELD_FORMAT;
					f->field = fmap[j].type;
					f->opt = 0;
					memset(&f->string, 0, sizeof(buffer));
					buffer_copy_string_len(&f->string, format + i + 2, k - (i + 2));

					++used;

					break;
				}

				if (fmap[j].key == '\0') {
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "%{...} has to be followed by a valid format-specifier");
				}

				start = k + 2;
				i = start - 1; /* skip the string */

				break;
			default:
				/* after the % has to be a character */
				if (format[i+1] == '\0') {
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "% has to be followed by a format-specifier");
				}

				for (j = 0; fmap[j].key != '\0'; j++) {
					if (fmap[j].key != format[i+1]) continue;

					/* found key */

					f = fptr+used;
					f->type = FIELD_FORMAT;
					f->field = fmap[j].type;
					f->string.ptr = NULL;
					f->opt = 0;

					++used;

					break;
				}

				if (fmap[j].key == '\0') {
					return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
					         "% has to be followed by a valid format-specifier");
				}

				start = i + 2;
				i = start - 1; /* skip the string */

				break;
			}
	}

	if (start < i) {
		/* copy the string */
		if (used == sz)
			return accesslog_parse_format_err(errh, __FILE__, __LINE__, fptr,
			         "too many fields (>= 127) in accesslog.format");

		f = fptr+used;
		f->type = FIELD_STRING;
		memset(&f->string, 0, sizeof(buffer));
		buffer_copy_string_len(&f->string, format + start, i - start);

		++used;
	}

	format_fields * const fields =
	  malloc(sizeof(format_fields) + ((used+1) * sizeof(format_field)));
	force_assert(fields);
	memset(fields, 0, sizeof(format_fields));
	memcpy(fields->ptr, fptr, (used+1) * sizeof(format_field));
	return fields;
}

static void mod_accesslog_free_format_fields(format_fields * const ff) {
    for (format_field *f = ff->ptr; f->type != FIELD_UNSET; ++f)
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
      default:/* should not happen */
        return;
    }
}

static void mod_accesslog_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_accesslog_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_accesslog_patch_config(request_st * const r, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_accesslog_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static format_fields * mod_accesslog_process_format(const char * const format, const size_t flen, server * const srv);

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
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_accesslog"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
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
              default:/* should not happen */
                break;
            }
        }

        if (srv->srvconf.preflight_check) continue;

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

    p->defaults.syslog_level = LOG_INFO;

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

static format_fields * mod_accesslog_process_format(const char * const format, const size_t flen, server * const srv) {
			format_fields * const parsed_format =
			  accesslog_parse_format(format, flen, srv->errh);
			if (NULL == parsed_format) {
				log_error(srv->errh, __FILE__, __LINE__,
					"parsing accesslog-definition failed: %s", format);
				return NULL;
			}

			uint32_t tcount = 0;
			for (format_field *f = parsed_format->ptr; f->type != FIELD_UNSET; ++f) {
				const buffer * const fstr = &f->string;
				if (FIELD_FORMAT != f->type) continue;
				if (FORMAT_TIMESTAMP == f->field) {
					if (!buffer_is_blank(fstr)) {
						const char *ptr = fstr->ptr;
						if (0 == strncmp(ptr, "begin:", sizeof("begin:")-1)) {
							f->opt |= FORMAT_FLAG_TIME_BEGIN;
							ptr += sizeof("begin:")-1;
						} else if (0 == strncmp(ptr, "end:", sizeof("end:")-1)) {
							f->opt |= FORMAT_FLAG_TIME_END;
							ptr += sizeof("end:")-1;
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
					srv->srvconf.high_precision_timestamps = 1;
				} else if (FORMAT_TIME_USED == f->field) {
					if (buffer_is_blank(fstr)
					      || buffer_is_equal_string(fstr, CONST_STR_LEN("s"))
					      || buffer_is_equal_string(fstr, CONST_STR_LEN("sec")))  f->opt |= FORMAT_FLAG_TIME_SEC;
					else if (buffer_is_equal_string(fstr, CONST_STR_LEN("ms"))
					      || buffer_is_equal_string(fstr, CONST_STR_LEN("msec"))) f->opt |= FORMAT_FLAG_TIME_MSEC;
					else if (buffer_is_equal_string(fstr, CONST_STR_LEN("us"))
					      || buffer_is_equal_string(fstr, CONST_STR_LEN("usec"))) f->opt |= FORMAT_FLAG_TIME_USEC;
					else if (buffer_is_equal_string(fstr, CONST_STR_LEN("ns"))
					      || buffer_is_equal_string(fstr, CONST_STR_LEN("nsec"))) f->opt |= FORMAT_FLAG_TIME_NSEC;
					else {
						log_error(srv->errh, __FILE__, __LINE__,
							"invalid time unit in %%{UNIT}T: %s", format);
						mod_accesslog_free_format_fields(parsed_format);
						return NULL;
					}

					if (f->opt & ~(FORMAT_FLAG_TIME_SEC)) srv->srvconf.high_precision_timestamps = 1;
				} else if (FORMAT_COOKIE == f->field) {
					if (buffer_is_blank(fstr)) f->type = FIELD_STRING; /*(blank)*/
				} else if (FORMAT_SERVER_PORT == f->field) {
					if (buffer_is_blank(fstr))
						f->opt |= FORMAT_FLAG_PORT_LOCAL;
					else if (buffer_is_equal_string(fstr, CONST_STR_LEN("canonical")))
						f->opt |= FORMAT_FLAG_PORT_LOCAL;
					else if (buffer_is_equal_string(fstr, CONST_STR_LEN("local")))
						f->opt |= FORMAT_FLAG_PORT_LOCAL;
					else if (buffer_is_equal_string(fstr, CONST_STR_LEN("remote")))
						f->opt |= FORMAT_FLAG_PORT_REMOTE;
					else {
						log_error(srv->errh, __FILE__, __LINE__,
							"invalid format %%{canonical,local,remote}p: %s", format);
						mod_accesslog_free_format_fields(parsed_format);
						return NULL;
					}
				} else if (FORMAT_HEADER == f->field
				           || FORMAT_RESPONSE_HEADER == f->field) {
					f->opt = http_header_hkey_get(BUF_PTR_LEN(fstr));
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

static int log_access_record (const request_st * const r, buffer * const b, format_fields * const parsed_format) {
	const connection * const con = r->con;
	const buffer *vb;
	unix_timespec64_t ts = { 0, 0 };
	int flush = 0;

	for (const format_field *f = parsed_format->ptr; f->type != FIELD_UNSET; ++f) {
		switch(f->type) {
		case FIELD_STRING:
			buffer_append_string_buffer(b, &f->string);
			break;
		case FIELD_FORMAT:
			switch(f->field) {
			case FORMAT_TIMESTAMP:

				if (f->opt & ~(FORMAT_FLAG_TIME_BEGIN|FORMAT_FLAG_TIME_END)) {
					if (f->opt & FORMAT_FLAG_TIME_SEC) {
						unix_time64_t t = (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) ? log_epoch_secs : r->start_hp.tv_sec;
						buffer_append_int(b, (intmax_t)t);
					} else if (f->opt & (FORMAT_FLAG_TIME_MSEC|FORMAT_FLAG_TIME_USEC|FORMAT_FLAG_TIME_NSEC)) {
						unix_time64_t t;
						long ns;
						if (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) {
							if (0 == ts.tv_sec) log_clock_gettime_realtime(&ts);
							t = ts.tv_sec;
							ns = ts.tv_nsec;
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
							if (0 == ts.tv_sec) log_clock_gettime_realtime(&ts);
							ns = ts.tv_nsec;
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
							break;
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
					                       fmt ? fmt : "[%d/%b/%Y:%T %z]",
					                       localtime64_r(&t, &tm));
				      #else /* HAVE_STRUCT_TM_GMTOFF */
					buffer_append_strftime(ts_accesslog_str,
					                       fmt ? fmt : "[%d/%b/%Y:%T +0000]",
					                       gmtime64_r(&t, &tm));
				      #endif /* HAVE_STRUCT_TM_GMTOFF */
					buffer_append_string_buffer(b, ts_accesslog_str);
				}
				break;
			case FORMAT_TIME_USED:
			case FORMAT_TIME_USED_US:
				if (f->opt & FORMAT_FLAG_TIME_SEC) {
					buffer_append_int(b, log_epoch_secs - r->start_hp.tv_sec);
				} else {
					const unix_timespec64_t * const bs = &r->start_hp;
					off_t tdiff; /*(expected to be 64-bit since large file support enabled)*/
					if (0 == ts.tv_sec) log_clock_gettime_realtime(&ts);
					tdiff = (off_t)(ts.tv_sec - bs->tv_sec)*1000000000 + (ts.tv_nsec - bs->tv_nsec);
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
				break;
			case FORMAT_REMOTE_ADDR:
			case FORMAT_REMOTE_HOST:
				buffer_append_string_buffer(b, &con->dst_addr_buf);
				break;
			case FORMAT_REMOTE_IDENT:
				/* ident */
				buffer_append_string_len(b, CONST_STR_LEN("-"));
				break;
			case FORMAT_REMOTE_USER:
				if (NULL != (vb = http_header_env_get(r, CONST_STR_LEN("REMOTE_USER")))) {
					accesslog_append_escaped(b, vb);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_REQUEST_LINE:
				/*(attempt to reconstruct request line)*/
				http_method_append(b, r->http_method);
				buffer_append_string_len(b, CONST_STR_LEN(" "));
				accesslog_append_escaped(b, &r->target_orig);
				buffer_append_string_len(b, CONST_STR_LEN(" "));
				http_version_append(b, r->http_version);
				break;
			case FORMAT_STATUS:
				buffer_append_int(b, r->http_status);
				break;

			case FORMAT_BYTES_OUT_NO_HEADER:
			{
				off_t bytes = r->http_version <= HTTP_VERSION_1_1
				  ? con->bytes_written - r->bytes_written_ckpt
				  : r->write_queue.bytes_out;
				if (bytes > 0) {
					bytes -= (off_t)r->resp_header_len;
					buffer_append_int(b, bytes > 0 ? bytes : 0);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			}
			case FORMAT_HEADER:
				if (NULL != (vb = http_header_request_get(r, f->opt, BUF_PTR_LEN(&f->string)))) {
					accesslog_append_escaped(b, vb);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_RESPONSE_HEADER:
				if (NULL != (vb = http_header_response_get(r, f->opt, BUF_PTR_LEN(&f->string)))) {
					accesslog_append_escaped(b, vb);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_ENV:
			case FORMAT_NOTE:
				if (NULL != (vb = http_header_env_get(r, BUF_PTR_LEN(&f->string)))) {
					accesslog_append_escaped(b, vb);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_FILENAME:
				if (!buffer_is_blank(&r->physical.path)) {
					buffer_append_string_buffer(b, &r->physical.path);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_BYTES_OUT:
			{
				off_t bytes = r->http_version <= HTTP_VERSION_1_1
				  ? con->bytes_written - r->bytes_written_ckpt
				  : r->write_queue.bytes_out;
				if (bytes > 0) {
					buffer_append_int(b, bytes);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			}
			case FORMAT_BYTES_IN:
			{
				off_t bytes = r->http_version <= HTTP_VERSION_1_1
				  ? con->bytes_read - r->bytes_read_ckpt
				  : r->read_queue.bytes_in + (off_t)r->rqst_header_len;
				if (bytes > 0) {
					buffer_append_int(b, bytes);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			}
			case FORMAT_SERVER_NAME:
				if (!buffer_is_blank(r->server_name)) {
					buffer_append_string_buffer(b, r->server_name);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_HTTP_HOST:
				if (!buffer_is_blank(&r->uri.authority)) {
					accesslog_append_escaped(b, &r->uri.authority);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_REQUEST_PROTOCOL:
				http_version_append(b, r->http_version);
				break;
			case FORMAT_REQUEST_METHOD:
				http_method_append(b, r->http_method);
				break;
			case FORMAT_PERCENT:
				buffer_append_string_len(b, CONST_STR_LEN("%"));
				break;
			case FORMAT_LOCAL_ADDR:
				{
					/* (perf: not using getsockname() and
					 *  sock_addr_cache_inet_ntop_copy_buffer())
					 * (still useful if admin has configured explicit listen IPs) */
					const server_socket * const srv_sock = con->srv_socket;
					buffer_append_string_len(b, srv_sock->srv_token->ptr,
					                         srv_sock->srv_token_colon);
				}
				break;
			case FORMAT_SERVER_PORT:
				if (f->opt & FORMAT_FLAG_PORT_REMOTE) {
					buffer_append_int(b, sock_addr_get_port(&con->dst_addr));
				} else { /* if (f->opt & FORMAT_FLAG_PORT_LOCAL) *//*(default)*/
					const server_socket * const srv_sock = con->srv_socket;
					const buffer * const srv_token = srv_sock->srv_token;
					const size_t tlen = buffer_clen(srv_token);
					size_t colon = srv_sock->srv_token_colon;
					if (colon < tlen) /*(colon != tlen)*/
						buffer_append_string_len(b, srv_token->ptr+colon+1,
						                         tlen - (colon+1));
				}
				break;
			case FORMAT_QUERY_STRING:
				accesslog_append_escaped(b, &r->uri.query);
				break;
			case FORMAT_URL:
				{
					const uint32_t len = buffer_clen(&r->target);
					const char * const qmark = memchr(r->target.ptr, '?', len);
					accesslog_append_escaped_str(b, r->target.ptr, qmark ? (uint32_t)(qmark - r->target.ptr) : len);
				}
				break;
			case FORMAT_CONNECTION_STATUS:
				if (r->state == CON_STATE_RESPONSE_END) {
					if (r->keep_alive <= 0) {
						buffer_append_string_len(b, CONST_STR_LEN("-"));
					} else {
						buffer_append_string_len(b, CONST_STR_LEN("+"));
					}
				} else { /* CON_STATE_ERROR */
					buffer_append_string_len(b, CONST_STR_LEN("X"));
				}
				break;
			case FORMAT_KEEPALIVE_COUNT:
				if (con->request_count > 1) {
					buffer_append_int(b, (intmax_t)(con->request_count-1));
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("0"));
				}
				break;
			case FORMAT_COOKIE:
				if (NULL != (vb = http_header_request_get(r, HTTP_HEADER_COOKIE, CONST_STR_LEN("Cookie")))) {
					char *str = vb->ptr;
					size_t len = buffer_clen(&f->string);
					do {
						while (*str == ' ' || *str == '\t') ++str;
						if (0 == strncmp(str, f->string.ptr, len) && str[len] == '=') {
							char *v = str+len+1;
							for (str = v; *str != '\0' && *str != ';'; ++str) ;
							if (str == v) break;
							do { --str; } while (str > v && (*str == ' ' || *str == '\t'));
							accesslog_append_escaped_str(b, v, str - v + 1);
							break;
						} else {
							while (*str != ';' && *str != ' ' && *str != '\t' && *str != '\0') ++str;
						}
						while (*str == ' ' || *str == '\t') ++str;
					} while (*str++ == ';');
				}
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
	}

	return flush;
}

REQUESTDONE_FUNC(log_access_write) {
    plugin_data * const p = p_d;
    mod_accesslog_patch_config(r, p);
    fdlog_st * const fdlog = p->conf.fdlog;

    /* No output device, nothing to do */
    if (!p->conf.use_syslog && !fdlog) return HANDLER_GO_ON;

    buffer * const b = (p->conf.use_syslog || fdlog->mode == FDLOG_PIPE)
      ? (buffer_clear(r->tmp_buf), r->tmp_buf)
      : &fdlog->b;

    const int flush = log_access_record(r, b, p->conf.parsed_format);

  #ifdef HAVE_SYSLOG_H
    if (p->conf.use_syslog) {
        if (!buffer_is_blank(b))
            syslog(p->conf.syslog_level, "%s", b->ptr);
        return HANDLER_GO_ON;
    }
  #endif

    buffer_append_string_len(b, CONST_STR_LEN("\n"));

    if (flush || fdlog->mode == FDLOG_PIPE || buffer_clen(b) >= 8192) {
        const ssize_t wr = write_all(fdlog->fd, BUF_PTR_LEN(b));
        buffer_clear(b); /*(clear buffer, even on error)*/
        if (-1 == wr)
            log_perror(r->conf.errh, __FILE__, __LINE__,
              "error flushing log %s", fdlog->fn);
    }

    return HANDLER_GO_ON;
}


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
