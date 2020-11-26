#include "first.h"

/**
 * angel process for lighttpd
 *
 * the purpose is the run as root all the time and handle:
 * - restart on crash
 * - spawn on HUP to allow graceful restart
 * - ...
 *
 * it has to stay safe and small to be trustable
 */

#ifdef _WIN32
#include <stdio.h>
int main (void) {
    fprintf(stderr, "lighttpd-angel is not implemented on Windows.  "
                    "Prefer using Windows services.\n");
    return 1;
}
#else /* ! _WIN32 */

#include <sys/wait.h>

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>     /* _exit() execvp() fork() */

#define BINPATH SBIN_DIR"/lighttpd"

static volatile sig_atomic_t restart = 0;
static pid_t pid = -1;

__attribute_cold__
static void signal_handler (int sig)
{
    if (pid <= 0) return;

    if (sig == SIGHUP) {
        /* trigger graceful shutdown of lighttpd, then restart lighttpd */
        sig = SIGINT;
        restart = -1;
    }

    /* forward signal to the child */
    kill(pid, sig);
}

__attribute_cold__
static void signal_setup (void)
{
    signal(SIGCHLD, SIG_DFL);
    signal(SIGALRM, SIG_DFL);

    signal(SIGPIPE, SIG_IGN);

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGHUP,  signal_handler);
}

__attribute_cold__
int main (int argc, char **argv)
{
    UNUSED(argc);
    *(const char **)&argv[0] = BINPATH;
  #ifdef __COVERITY__
    __coverity_tainted_data_sanitize__(argv);
  #endif

    signal_setup();

    do {

        if (-1 == pid) {
            pid = fork();
            if (-1 == pid) return -1;
            if (0 == pid) {
                /* intentionally pass argv params */
                /* coverity[tainted_string : FALSE] */
                execvp(argv[0], argv);
                _exit(1);
            }
        }

        int exitcode = 0;
        if ((pid_t)-1 == waitpid(pid, &exitcode, 0)) {
            if (errno == ECHILD) break; /* child exists; should not happen */
            continue;
        }

        const char *msg = NULL;
        int code = 0;
        if (WIFEXITED(exitcode)) {
            code = WEXITSTATUS(exitcode);
            msg = "%s.%d: child (pid=%d) exited normally with exitcode: %d\n";
        }
        else if (WIFSIGNALED(exitcode)) {
            code = WTERMSIG(exitcode);
            msg = "%s.%d: child (pid=%d) exited unexpectedly with signal %d, "
                  "restarting\n";
            restart = -1;
        }
        if (msg)
            fprintf(stderr, msg, __FILE__, __LINE__, pid, code);

        pid = restart; /* -1 for restart, 0 to exit */
        restart = 0;

    } while (pid != 0);

    return 0;
}

#endif /* ! _WIN32 */
