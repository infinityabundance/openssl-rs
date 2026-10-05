/*
 * openssl-rs — Phase 17 downstream (HAProxy): SIGSEGV backtrace catcher.
 *
 * External instrumentation only: this shared object is LD_PRELOAD-ed into the *unmodified*
 * candidate-linked HAProxy to capture a stack trace when it dies on a TLS handshake. It does not
 * touch HAProxy, the candidate, or the authority; it installs a fatal-signal handler whose only
 * job is to dump a backtrace and re-raise. It exists purely for evidence (the image has no gdb).
 */
#define _GNU_SOURCE
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <stdlib.h>

static void handler(int sig)
{
    void *bt[64];
    int n = backtrace(bt, 64);
    backtrace_symbols_fd(bt, n, 2); /* fd 2 = stderr of the haproxy process */
    signal(sig, SIG_DFL);
    raise(sig);
}

__attribute__((constructor)) static void install_handlers(void)
{
    signal(SIGSEGV, handler);
    signal(SIGABRT, handler);
    signal(SIGBUS, handler);
    signal(SIGILL, handler);
}
