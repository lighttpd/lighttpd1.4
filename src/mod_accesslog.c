#include "first.h"

#include "base.h"
#include "fdevent.h"
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
#include <time.h>

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
    time_t last_generated_accesslog_ts;
    buffer ts_accesslog_str;
  #if defined(__STDC_VERSION__) && __STDC_VERSION__-0 >= 199901L /* C99 */
    format_field ptr[];  /* C99 VLA */
  #else
    format_field ptr[1];
  #endif
} format_fields;

typedef struct {
	int    log_access_fd;
	char use_syslog; /* syslog has global buffer */
	char piped_logger;
	unsigned short syslog_level;
	buffer *access_logbuffer; /* each logfile has a separate buffer */
	const buffer *access_logfile;

	format_fields *parsed_format;
} plugin_config;

typedef struct {
    int log_access_fd;
    char piped_logger;
    const buffer *access_logfile;
    buffer access_logbuffer; /* each logfile has a separate buffer */
} accesslog_st;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    buffer syslog_logbuffer; /* syslog has global buffer. no caching, always written directly */
    log_error_st *errh; /* copy of srv->errh */
    format_fields *default_format;/* allocated if default format */
} plugin_data;

INIT_FUNC(mod_accesslog_init) {
    return calloc(1, sizeof(plugin_data));
}

static int accesslog_write_all(const int fd, buffer * const b) {
    const ssize_t wr = (fd >= 0) ? write_all(fd, CONST_BUF_LEN(b)) : 0;
    buffer_clear(b); /*(clear buffer, even if fd < 0)*/
    return (-1 != wr);
}

static void accesslog_append_escaped_str(buffer *dest, char *str, size_t len) {
	char *ptr, *start, *end;

	/* replaces non-printable chars with \xHH where HH is the hex representation of the byte */
	/* exceptions: " => \", \ => \\, whitespace chars => \n \t etc. */
	if (0 == len) return;
	buffer_string_prepare_append(dest, len);

	for (ptr = start = str, end = str+len; ptr < end; ++ptr) {
		unsigned char const c = (unsigned char) *ptr;
		if (c >= ' ' && c <= '~' && c != '"' && c != '\\') {
			/* nothing to change, add later as one block */
		} else {
			/* copy previous part */
			if (start < ptr) {
				buffer_append_string_len(dest, start, ptr - start);
			}
			start = ptr + 1;

			switch (c) {
			case '"':
				BUFFER_APPEND_STRING_CONST(dest, "\\\"");
				break;
			case '\\':
				BUFFER_APPEND_STRING_CONST(dest, "\\\\");
				break;
			case '\b':
				BUFFER_APPEND_STRING_CONST(dest, "\\b");
				break;
			case '\n':
				BUFFER_APPEND_STRING_CONST(dest, "\\n");
				break;
			case '\r':
				BUFFER_APPEND_STRING_CONST(dest, "\\r");
				break;
			case '\t':
				BUFFER_APPEND_STRING_CONST(dest, "\\t");
				break;
			case '\v':
				BUFFER_APPEND_STRING_CONST(dest, "\\v");
				break;
			default: {
					/* non printable char => \xHH */
					char hh[5] = {'\\','x',0,0,0};
					char h = c / 16;
					hh[2] = (h > 9) ? (h - 10 + 'A') : (h + '0');
					h = c % 16;
					hh[3] = (h > 9) ? (h - 10 + 'A') : (h + '0');
					buffer_append_string_len(dest, &hh[0], 4);
				}
				break;
			}
		}
	}

	if (start < end) {
		buffer_append_string_len(dest, start, end - start);
	}
}

static void accesslog_append_escaped(buffer *dest, const buffer *str) {
	accesslog_append_escaped_str(dest, CONST_BUF_LEN(str));
}

__attribute_cold__
static format_fields * accesslog_parse_format_err(server *srv, const char *file, unsigned int line, format_field *f, const char *msg) {
    log_error(srv->errh, file, line, "%s", msg);
    for (; f->type != FIELD_UNSET; ++f) free(f->string.ptr);
    return NULL;
}

static format_fields * accesslog_parse_format(server *srv, const char *format, const size_t flen) {
	/* common log format (the default) results in 18 elements,
	 * so 127 should be enough except for obscene custom usage */
	size_t i, j, k = 0, start = 0;
	uint32_t used = 0;
	const uint32_t sz = 127;
	format_field *f;
	format_field fptr[sz+1]; /* (128 elements takes 4k on stack in 64-bit) */
	memset(fptr, 0, sizeof(fptr));
	if (0 != FIELD_UNSET) return NULL;

	if (0 == flen) return NULL;

	for (i = 0; i < flen; ++i) {
		if (format[i] != '%') continue;

			if (i > 0 && start != i) {
				/* copy the string before this % */
				if (used == sz)
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
					         "too many fields (>= 127) in accesslog.format");

				f = fptr+used;
				f->type = FIELD_STRING;
				memset(&f->string, 0, sizeof(buffer));
				buffer_copy_string_len(&f->string, format + start, i - start);

				++used;
			}

			/* we need a new field */
			if (used == sz)
				return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
				         "too many fields (>= 127) in accesslog.format");

			/* search for the terminating command */
			switch (format[i+1]) {
			case '>':
			case '<':
				/* after the } has to be a character */
				if (format[i+2] == '\0') {
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
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
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
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
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
					         "%{ has to be terminated by a }");
				}

				/* after the } has to be a character */
				if (format[k+1] == '\0') {
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
					         "%{...} has to be followed by a format-specifier");
				}

				if (k == i + 2) {
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
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
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
					         "%{...} has to be followed by a valid format-specifier");
				}

				start = k + 2;
				i = start - 1; /* skip the string */

				break;
			default:
				/* after the % has to be a character */
				if (format[i+1] == '\0') {
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
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
					return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
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
			return accesslog_parse_format_err(srv, __FILE__, __LINE__, fptr,
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

static void mod_accesslog_free_accesslog(accesslog_st * const x, plugin_data *p) {
    /*(piped loggers are closed in fdevent_close_logger_pipes())*/
    if (!x->piped_logger && -1 != x->log_access_fd) {
        if (!accesslog_write_all(x->log_access_fd, &x->access_logbuffer)) {
            log_perror(p->errh, __FILE__, __LINE__,
              "writing access log entry failed: %s", x->access_logfile->ptr);
        }
        close(x->log_access_fd);
    }
    free(x->access_logbuffer.ptr);
}

static void mod_accesslog_free_format_fields(format_fields * const ff) {
    for (format_field *f = ff->ptr; f->type != FIELD_UNSET; ++f)
        free(f->string.ptr);
    free(ff->ts_accesslog_str.ptr);
    free(ff);
}

FREE_FUNC(mod_accesslog_free) {
    plugin_data * const p = p_d;
    free(p->syslog_logbuffer.ptr);
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 0: /* accesslog.filename */
                mod_accesslog_free_accesslog(cpv->v.v, p);
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
        accesslog_st * const x = cpv->v.v;
        pconf->log_access_fd    = x->log_access_fd;
        pconf->piped_logger     = x->piped_logger;
        pconf->access_logfile   = x->access_logfile;
        pconf->access_logbuffer = &x->access_logbuffer;
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

static void mod_accesslog_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_accesslog_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static format_fields * mod_accesslog_process_format(server * const srv, const char * const format, const size_t flen);

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
    p->errh = srv->errh;
    if (!config_plugin_values_init(srv, p, cpk, "mod_accesslog"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        int use_syslog = 0;
        accesslog_st *x = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* accesslog.filename */
                x = calloc(1, sizeof(accesslog_st));
                force_assert(x);
                x->log_access_fd = -1;
                x->piped_logger = (cpv->v.b->ptr[0] == '|');
                x->access_logfile = cpv->v.b;
                cpv->vtype = T_CONFIG_LOCAL;
                cpv->v.v = x;
                break;
              case 1: /* accesslog.format */
                cpv->v.v =
                  mod_accesslog_process_format(srv, CONST_BUF_LEN(cpv->v.b));
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
        if (NULL == x || buffer_string_is_empty(x->access_logfile)) continue;

        x->log_access_fd = fdevent_open_logger(x->access_logfile->ptr);
        if (-1 == x->log_access_fd) {
            log_perror(srv->errh, __FILE__, __LINE__,
              "opening log '%s' failed", x->access_logfile->ptr);
            return HANDLER_ERROR;
        }
    }

    p->defaults.log_access_fd = -1;
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
          mod_accesslog_process_format(srv, CONST_STR_LEN(fmt));
        if (NULL == p->default_format) return HANDLER_ERROR;
    }

    return HANDLER_GO_ON;
}

static format_fields * mod_accesslog_process_format(server * const srv, const char * const format, const size_t flen) {
			format_fields * const parsed_format =
			  accesslog_parse_format(srv, format, flen);
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
					if (!buffer_string_is_empty(fstr)) {
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
					if (buffer_string_is_empty(fstr)
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
					if (buffer_string_is_empty(fstr)) f->type = FIELD_STRING; /*(blank)*/
				} else if (FORMAT_SERVER_PORT == f->field) {
					if (buffer_string_is_empty(fstr))
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
				}
			}

			return parsed_format;
}

static void log_access_flush(plugin_data * const p) {
    /* future: might be slightly faster to have allocated array of open files
     * rather than walking config, but only might matter with many directives */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* accesslog.filename */
                if (cpv->vtype == T_CONFIG_LOCAL && NULL != cpv->v.v) {
                    accesslog_st * const x = cpv->v.v;
                    if (buffer_string_is_empty(&x->access_logbuffer)) continue;
                    if (!accesslog_write_all(x->log_access_fd,
                                             &x->access_logbuffer)) {
                        log_perror(p->errh, __FILE__, __LINE__,
                          "writing access log entry failed: %s",
                          x->access_logfile->ptr);
                    }
                }
                break;
              default:
                break;
            }
        }
    }
}

TRIGGER_FUNC(log_access_periodic_flush) {
	/* flush buffered access logs every 4 seconds */
	if (0 == (srv->cur_ts & 3)) log_access_flush((plugin_data *)p_d);
	return HANDLER_GO_ON;
}

SIGHUP_FUNC(log_access_cycle) {
    plugin_data * const p = p_d;

    log_access_flush(p);

    /* future: might be slightly faster to have allocated array of open files
     * rather than walking config, but only might matter with many directives */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 0:{/* accesslog.filename */
                accesslog_st * const x = cpv->v.v;
                if (x->piped_logger) continue;
                if (buffer_string_is_empty(x->access_logfile)) continue;
                if (-1 == fdevent_cycle_logger(x->access_logfile->ptr,
                                               &x->log_access_fd)) {
                    log_perror(srv->errh, __FILE__, __LINE__,
                      "cycling access log failed: %s", x->access_logfile->ptr);
                }
                break;
              }
              default:
                break;
            }
        }
    }

    return HANDLER_GO_ON;
}

REQUESTDONE_FUNC(log_access_write) {
	plugin_data *p = p_d;
	mod_accesslog_patch_config(con, p);

	/* No output device, nothing to do */
	if (!p->conf.use_syslog && p->conf.log_access_fd == -1) return HANDLER_GO_ON;

	buffer * const b = (p->conf.use_syslog)
	  ? &p->syslog_logbuffer
	  : p->conf.access_logbuffer;

	const buffer *vb;
	struct timespec ts = { 0, 0 };

	int flush = p->conf.piped_logger;

	for (const format_field *f = p->conf.parsed_format->ptr; f->type != FIELD_UNSET; ++f) {
		switch(f->type) {
		case FIELD_STRING:
			buffer_append_string_buffer(b, &f->string);
			break;
		case FIELD_FORMAT:
			switch(f->field) {
			case FORMAT_TIMESTAMP:

				if (f->opt & ~(FORMAT_FLAG_TIME_BEGIN|FORMAT_FLAG_TIME_END)) {
					if (f->opt & FORMAT_FLAG_TIME_SEC) {
						time_t t = (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) ? con->srv->cur_ts : con->request_start;
						buffer_append_int(b, (intmax_t)t);
					} else if (f->opt & (FORMAT_FLAG_TIME_MSEC|FORMAT_FLAG_TIME_USEC|FORMAT_FLAG_TIME_NSEC)) {
						off_t t; /*(expected to be 64-bit since large file support enabled)*/
						long ns;
						if (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) {
							if (0 == ts.tv_sec) log_clock_gettime_realtime(&ts);
							t = (off_t)ts.tv_sec;
							ns = ts.tv_nsec;
						} else {
							t = (off_t)con->request_start_hp.tv_sec;
							ns = con->request_start_hp.tv_nsec;
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
							ns = con->request_start_hp.tv_nsec;
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
						for (ptr = b->ptr + buffer_string_length(b); ns > 0; ns /= 10)
							*--ptr = (ns % 10) + '0';
					}
				} else {
					format_fields * const parsed_format = p->conf.parsed_format;
					buffer * const ts_accesslog_str = &parsed_format->ts_accesslog_str;
					/* cache the generated timestamp (only if ! FORMAT_FLAG_TIME_BEGIN) */
					struct tm *tmptr;
					time_t t;
				      #if defined(HAVE_STRUCT_TM_GMTOFF)
				      # ifdef HAVE_LOCALTIME_R
					struct tm tm;
				      # endif /* HAVE_LOCALTIME_R */
				      #else /* HAVE_STRUCT_TM_GMTOFF */
				      # ifdef HAVE_GMTIME_R
					struct tm tm;
				      # endif /* HAVE_GMTIME_R */
				      #endif /* HAVE_STRUCT_TM_GMTOFF */

					if (!(f->opt & FORMAT_FLAG_TIME_BEGIN)) {
						const time_t cur_ts = con->srv->cur_ts;
						if (parsed_format->last_generated_accesslog_ts == cur_ts) {
							buffer_append_string_buffer(b, ts_accesslog_str);
							break;
						}
						t = parsed_format->last_generated_accesslog_ts = cur_ts;
						flush = 1;
					} else {
						t = con->request_start;
					}

				      #if defined(HAVE_STRUCT_TM_GMTOFF)
				      # ifdef HAVE_LOCALTIME_R
					tmptr = localtime_r(&t, &tm);
				      # else /* HAVE_LOCALTIME_R */
					tmptr = localtime(&t);
				      # endif /* HAVE_LOCALTIME_R */
				      #else /* HAVE_STRUCT_TM_GMTOFF */
				      # ifdef HAVE_GMTIME_R
					tmptr = gmtime_r(&t, &tm);
				      # else /* HAVE_GMTIME_R */
					tmptr = gmtime(&t);
				      # endif /* HAVE_GMTIME_R */
				      #endif /* HAVE_STRUCT_TM_GMTOFF */

					buffer_clear(ts_accesslog_str);

					if (buffer_string_is_empty(&f->string)) {
					      #if defined(HAVE_STRUCT_TM_GMTOFF)
						long scd, hrs, min;
						buffer_append_strftime(ts_accesslog_str, "[%d/%b/%Y:%H:%M:%S ", tmptr);
						buffer_append_string_len(ts_accesslog_str, tmptr->tm_gmtoff >= 0 ? "+" : "-", 1);

						scd = labs(tmptr->tm_gmtoff);
						hrs = scd / 3600;
						min = (scd % 3600) / 60;

						/* hours */
						if (hrs < 10) buffer_append_string_len(ts_accesslog_str, CONST_STR_LEN("0"));
						buffer_append_int(ts_accesslog_str, hrs);

						if (min < 10) buffer_append_string_len(ts_accesslog_str, CONST_STR_LEN("0"));
						buffer_append_int(ts_accesslog_str, min);
						buffer_append_string_len(ts_accesslog_str, CONST_STR_LEN("]"));
					      #else
						buffer_append_strftime(ts_accesslog_str, "[%d/%b/%Y:%H:%M:%S +0000]", tmptr);
					      #endif /* HAVE_STRUCT_TM_GMTOFF */
					} else {
						buffer_append_strftime(ts_accesslog_str, f->string.ptr, tmptr);
					}

					buffer_append_string_buffer(b, ts_accesslog_str);
				}
				break;
			case FORMAT_TIME_USED:
			case FORMAT_TIME_USED_US:
				if (f->opt & FORMAT_FLAG_TIME_SEC) {
					buffer_append_int(b, con->srv->cur_ts - con->request_start);
				} else {
					const struct timespec * const bs = &con->request_start_hp;
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
				buffer_append_string_buffer(b, con->dst_addr_buf);
				break;
			case FORMAT_REMOTE_IDENT:
				/* ident */
				buffer_append_string_len(b, CONST_STR_LEN("-"));
				break;
			case FORMAT_REMOTE_USER:
				if (NULL != (vb = http_header_env_get(con, CONST_STR_LEN("REMOTE_USER")))) {
					accesslog_append_escaped(b, vb);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_REQUEST_LINE:
				/*(attempt to reconstruct request line)*/
				buffer_append_string(b, get_http_method_name(con->request.http_method));
				buffer_append_string_len(b, CONST_STR_LEN(" "));
				accesslog_append_escaped(b, con->request.orig_uri);
				buffer_append_string_len(b, CONST_STR_LEN(" "));
				buffer_append_string(b, get_http_version_name(con->request.http_version));
				break;
			case FORMAT_STATUS:
				buffer_append_int(b, con->http_status);
				break;

			case FORMAT_BYTES_OUT_NO_HEADER:
				if (con->bytes_written > 0) {
					buffer_append_int(b,
							    con->bytes_written - con->bytes_header <= 0 ? 0 : con->bytes_written - con->bytes_header);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_HEADER:
				if (NULL != (vb = http_header_request_get(con, HTTP_HEADER_UNSPECIFIED, CONST_BUF_LEN(&f->string)))) {
					accesslog_append_escaped(b, vb);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_RESPONSE_HEADER:
				if (NULL != (vb = http_header_response_get(con, HTTP_HEADER_UNSPECIFIED, CONST_BUF_LEN(&f->string)))) {
					accesslog_append_escaped(b, vb);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_ENV:
			case FORMAT_NOTE:
				if (NULL != (vb = http_header_env_get(con, CONST_BUF_LEN(&f->string)))) {
					accesslog_append_escaped(b, vb);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_FILENAME:
				if (!buffer_string_is_empty(con->physical.path)) {
					buffer_append_string_buffer(b, con->physical.path);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_BYTES_OUT:
				if (con->bytes_written > 0) {
					buffer_append_int(b, con->bytes_written);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_BYTES_IN:
				if (con->bytes_read > 0) {
					buffer_append_int(b, con->bytes_read);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_SERVER_NAME:
				if (!buffer_string_is_empty(con->server_name)) {
					buffer_append_string_buffer(b, con->server_name);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_HTTP_HOST:
				if (!buffer_string_is_empty(con->uri.authority)) {
					accesslog_append_escaped(b, con->uri.authority);
				} else {
					buffer_append_string_len(b, CONST_STR_LEN("-"));
				}
				break;
			case FORMAT_REQUEST_PROTOCOL:
				buffer_append_string_len(b,
					con->request.http_version == HTTP_VERSION_1_1 ? "HTTP/1.1" : "HTTP/1.0", 8);
				break;
			case FORMAT_REQUEST_METHOD:
				http_method_append(b, con->request.http_method);
				break;
			case FORMAT_PERCENT:
				buffer_append_string_len(b, CONST_STR_LEN("%"));
				break;
			case FORMAT_LOCAL_ADDR:
				{
					/* (perf: not using getsockname() and inet_ntop_cache_get_ip())
					 * (still useful if admin has configured explicit listen IPs) */
					const char *colon;
					buffer *srvtoken = con->srv_socket->srv_token;
					if (srvtoken->ptr[0] == '[') {
						colon = strstr(srvtoken->ptr, "]:");
					} else {
						colon = strchr(srvtoken->ptr, ':');
					}
					if (colon) {
						buffer_append_string_len(b, srvtoken->ptr, (size_t)(colon - srvtoken->ptr));
					} else {
						buffer_append_string_buffer(b, srvtoken);
					}
				}
				break;
			case FORMAT_SERVER_PORT:
				if (f->opt & FORMAT_FLAG_PORT_REMOTE) {
					buffer_append_int(b, sock_addr_get_port(&con->dst_addr));
				} else { /* if (f->opt & FORMAT_FLAG_PORT_LOCAL) *//*(default)*/
					const char *colon;
					buffer *srvtoken = ((server_socket*)(con->srv_socket))->srv_token;
					if (srvtoken->ptr[0] == '[') {
						colon = strstr(srvtoken->ptr, "]:");
					} else {
						colon = strchr(srvtoken->ptr, ':');
					}
					if (colon) {
						buffer_append_string(b, colon+1);
					} else {
						buffer_append_int(b, con->srv->srvconf.port);
					}
				}
				break;
			case FORMAT_QUERY_STRING:
				accesslog_append_escaped(b, con->uri.query);
				break;
			case FORMAT_URL:
				accesslog_append_escaped(b, con->uri.path_raw);
				break;
			case FORMAT_CONNECTION_STATUS:
				if (con->state == CON_STATE_RESPONSE_END) {
					if (0 == con->keep_alive) {
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
				if (NULL != (vb = http_header_request_get(con, HTTP_HEADER_COOKIE, CONST_STR_LEN("Cookie")))) {
					char *str = vb->ptr;
					size_t len = buffer_string_length(&f->string);
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

	if (p->conf.use_syslog) { /* syslog doesn't cache */
#ifdef HAVE_SYSLOG_H
		if (!buffer_string_is_empty(b)) {
			/*(syslog appends a \n on its own)*/
			syslog(p->conf.syslog_level, "%s", b->ptr);
		}
#endif
		buffer_clear(b);
	}
	else {
		buffer_append_string_len(b, CONST_STR_LEN("\n"));

		if (flush || buffer_string_length(b) >= BUFFER_MAX_REUSE_SIZE) {
			if (!accesslog_write_all(p->conf.log_access_fd, b)) {
				log_perror(con->conf.errh, __FILE__, __LINE__,
				  "writing access log entry failed: %s",
				  p->conf.access_logfile->ptr);
			}
		}
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
	p->handle_sighup        = log_access_cycle;

	return 0;
}
