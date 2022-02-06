/*
 * sys-setjmp - wrap system setjmp or compiler C try/catch mechanism
 *
 * Copyright(c) 2022 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"
#include "sys-setjmp.h"

#ifndef _MSC_VER

#ifdef HAVE_SIGNAL
#include <signal.h>     /* sig_atomic_t */
#else
typedef int sig_atomic_t;
#endif

#include <errno.h>
#include <setjmp.h>     /* sigjmp_buf sigsetjmp() siglongjmp() */
#include "ck.h"

/*(note: would need to be thread-local to be thread-safe)*/
static volatile sig_atomic_t sys_setjmp_sigbus_jmp_valid;
#ifdef _WIN32
static jmp_buf sys_setjmp_sigbus_jmp_buf;
#else
static sigjmp_buf sys_setjmp_sigbus_jmp_buf;
#endif

__attribute_noreturn__
void sys_setjmp_sigbus (int sig)
{
    UNUSED(sig);
  #ifdef _WIN32
    if (sys_setjmp_sigbus_jmp_valid) longjmp(sys_setjmp_sigbus_jmp_buf, 1);
  #else
    if (sys_setjmp_sigbus_jmp_valid) siglongjmp(sys_setjmp_sigbus_jmp_buf, 1);
  #endif
    ck_bt_abort(__FILE__, __LINE__, "SIGBUS");
}

/* Note: must have configured signal handler for macros to be effective
 *       e.g. signal(SIGBUS, sys_setjmp_sigbus)
 */

/* Note: should not 'return', 'break', 'continue', 'goto' out of try block,
 *       or else sys_setjmp_sigbus_jmp_valid will not be unset.  However, those
 *       are permitted from catch block when using these macros.  (In practice,
 *       unsetting sys_setjmp_sigbus_jmp_valid is not critical, since SIGBUS
 *       should not be received outside of the protected blocks, or else
 *       something (elsewhere) is missing protection to catch SIGBUS.)
 */

/* Note: sigaction() config in server.c sets SA_NODEFER and empty signal mask
 * so we avoid saving and restoring signal mask on systems with sigaction() */

#ifdef _WIN32
#define if_SYS_SETJMP_TRY()     if ((sys_setjmp_sigbus_jmp_valid = \
                                      !setjmp(sys_setjmp_sigbus_jmp_buf))) {
#elif defined(HAVE_SIGACTION)
#define if_SYS_SETJMP_TRY()     if ((sys_setjmp_sigbus_jmp_valid = \
                                      !sigsetjmp(sys_setjmp_sigbus_jmp_buf, 0))) {
#else
#define if_SYS_SETJMP_TRY()     if ((sys_setjmp_sigbus_jmp_valid = \
                                      !sigsetjmp(sys_setjmp_sigbus_jmp_buf, 1))) {
#endif

#define else_SYS_SETJMP_CATCH() } \
                                else { \

#define fi_SYS_SETJMP_END()     } \
                                sys_setjmp_sigbus_jmp_valid = 0;

#else /* _MSC_VER */

#include <windows.h>    /* winnt.h EXCEPTION_IN_PAGE_ERROR */
#include <excpt.h>

#define if_SYS_SETJMP_TRY()     __try {

#define else_SYS_SETJMP_CATCH() } \
                                __except ( \
                                  GetExceptionCode()==EXCEPTION_IN_PAGE_ERROR \
                                    ? EXCEPTION_EXECUTE_HANDLER \
                                    : EXCEPTION_CONTINUE_SEARCH ) {

#define fi_SYS_SETJMP_END()     }

#endif /* _MSC_VER */

off_t sys_setjmp_eval3(off_t(*cb)(void *, const void *, off_t), void *dst, const void *src, off_t len)
{
    off_t rv;
    if_SYS_SETJMP_TRY()
        rv = cb(dst, src, len);
    else_SYS_SETJMP_CATCH() {
      #ifndef _MSC_VER
        errno = EFAULT;
      #endif
        return -1;
    }
    fi_SYS_SETJMP_END()
    return rv;
}
