/*
 * sys-wait.h - sys/wait.h wrapper
 *
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_SYS_WAIT_H
#define INCLUDED_SYS_WAIT_H
#include "first.h"

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef _WIN32

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#endif

#ifndef WIFEXITED
#define WIFEXITED(status)   (((status) & 0x7f) == 0)
#endif

#ifndef WIFSIGNALED
#define WIFSIGNALED(status) \
  (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)
#endif

#ifndef WTERMSIG
#define WTERMSIG(status)    ((status) & 0x7f)
#endif

#endif /* _WIN32 */

#endif
