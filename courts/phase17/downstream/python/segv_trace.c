/*
 * openssl-rs — Phase 17 downstream: a SIGSEGV/SIGABRT backtrace preload.
 *
 * gdb is absent from the court image, so this tiny shared object installs a
 * SA_SIGINFO handler that prints the faulting address, the instruction pointer
 * and a raw frame-pointer walk (plus /proc/self/maps) before exiting. It is
 * diagnostic tooling only; it is not part of any court.
 *
 * Build:
 *   gcc -shared -fPIC -g -O0 -o /tmp/segv_trace.so /work/courts/phase17/downstream/python/segv_trace.c
 * Run:
 *   LD_PRELOAD=/tmp/segv_trace.so <cmd>
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

static void wstr(const char *s)
{
    ssize_t w = write(2, s, strlen(s));
    (void)w;
}

static void dump_maps(void)
{
    char buf[4096];
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0)
        return;
    int out = open("/tmp/segv_maps.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (out >= 0) {
            ssize_t w = write(out, buf, (size_t)n);
            (void)w;
        }
    }
    close(fd);
    if (out >= 0)
        close(out);
}

static void handler(int sig, siginfo_t *si, void *uc)
{
    ucontext_t *u = (ucontext_t *)uc;
    unsigned long rip = u->uc_mcontext.gregs[REG_RIP];
    unsigned long rbp = u->uc_mcontext.gregs[REG_RBP];
    unsigned long rsp = u->uc_mcontext.gregs[REG_RSP];
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
                     "\n[segv-trace] sig=%d addr=%p rip=%p rbp=%p rsp=%p\n",
                     sig, si->si_addr, (void *)rip, (void *)rbp, (void *)rsp);
    ssize_t w = write(2, buf, (size_t)n);
    (void)w;
    dump_maps();
    int sf = open("/tmp/segv_stack.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (sf >= 0) {
        unsigned long top = (unsigned long)si->si_addr;
        unsigned long len = (top > rsp) ? (top - rsp) : 0x1000;
        if (len > 0x100000)
            len = 0x100000;
        ssize_t w = write(sf, (void *)rsp, len);
        (void)w;
        close(sf);
    }
    wstr("[segv-trace] frame walk:\n");
    for (int i = 0; i < 120; i++) {
        if (rbp < 0x100000 || (rbp & 7) != 0)
            break;
        unsigned long *p = (unsigned long *)rbp;
        unsigned long ret = p[1];
        unsigned long next = p[0];
        n = snprintf(buf, sizeof(buf), "  #%02d rbp=%p ret=%p\n",
                     i, (void *)rbp, (void *)ret);
        w = write(2, buf, (size_t)n);
        (void)w;
        if (next <= rbp)
            break;
        rbp = next;
    }
    _exit(139);
}

static char altstack[256 * 1024];

__attribute__((constructor)) static void install(void)
{
    stack_t ss;
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}
