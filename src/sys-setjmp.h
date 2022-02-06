/*
 * sys-setjmp - wrap system setjmp or compiler C try/catch mechanism
 *
 * Copyright(c) 2022 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef LI_SYS_SETJMP_H
#define LI_SYS_SETJMP_H
#include "first.h"

#ifndef _MSC_VER
void sys_setjmp_sigbus (int sig);
#endif

off_t sys_setjmp_eval3(off_t(*cb)(void *, const void *, off_t), void *dst, const void *src, off_t len);

#endif /* LI_SYS_SETJMP_H */
