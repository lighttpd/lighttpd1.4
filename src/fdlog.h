#ifndef INCLUDED_FDLOG_H
#define INCLUDED_FDLOG_H
#include "first.h"

__attribute_cold__
int fdlog_open (const char *fn);

__attribute_cold__
int fdlog_cycle (const char *fn, int *curfd);

__attribute_cold__
int fdlog_pipes_waitpid_cb (pid_t pid);

__attribute_cold__
void fdlog_pipes_restart (unix_time64_t ts);

__attribute_cold__
void fdlog_pipes_close (void);

__attribute_cold__
void fdlog_pipes_abandon_pids (void);

__attribute_cold__
void fdlog_pipe_serrh (int fd);

#endif
