#ifndef INCLUDED_FDLOG_H
#define INCLUDED_FDLOG_H
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

struct fdlog_st {
    enum { FDLOG_FILE, FDLOG_FD, FDLOG_SYSLOG, FDLOG_PIPE } mode;
    int fd;
    buffer b;
    const char *fn;
};

__attribute_cold__
__attribute_returns_nonnull__
fdlog_st * fdlog_init (const char *fn, int fd, int mode);

__attribute_cold__
void fdlog_free (fdlog_st *fdlog);

/* fdlog_maint.c */

__attribute_cold__
fdlog_st * fdlog_open (const char *fn);

__attribute_cold__
void fdlog_closeall (fdlog_st *errh);

__attribute_cold__
void fdlog_flushall (fdlog_st *errh);

__attribute_cold__
void fdlog_files_flush (fdlog_st *errh, int memrel);

__attribute_cold__
void fdlog_files_cycle (fdlog_st *errh);

__attribute_cold__
int fdlog_pipes_waitpid_cb (pid_t pid);

__attribute_cold__
void fdlog_pipes_restart (unix_time64_t ts);

__attribute_cold__
void fdlog_pipes_abandon_pids (void);

__attribute_cold__
void fdlog_pipe_serrh (int fd);

#ifdef HAVE_SYSLOG_H
__attribute_cold__
void fdlog_closelog (void);

__attribute_cold__
void fdlog_openlog (fdlog_st *errh, const buffer *syslog_facility);
#endif

#endif
