/*
 * RT-TLS13-INTEROP-MATRIX — the 2x2 interoperability driver.
 *
 * Runs four cells over a real AF_UNIX `socketpair(AF_UNIX, SOCK_STREAM)`:
 *
 *     authority-client  <-> authority-server
 *     candidate-client  <-> authority-server   (cross)
 *     authority-client  <-> candidate-server   (cross)
 *     candidate-client  <-> candidate-server
 *
 * Each cell forks two processes and execs one peer binary per side, so exactly one implementation
 * is loaded per process and the two meet over the ABI and the wire. The driver links no TLS
 * library itself; it only owns the socketpair, the child lifetimes and the deterministic
 * `cell=<name>.<side>.<key>=<value>` transcript it re-emits from each peer's stdout.
 *
 * Nothing nondeterministic is printed: no clock, address, PID, or temp path.
 *
 * argv: <authority-peer> <authority-modules> <candidate-peer> <candidate-modules> <fixtures-dir>
 *
 * Each peer carries its own `-Wl,-rpath`, and the child unsets `LD_LIBRARY_PATH` before exec so
 * the rpath (and not a shared environment) selects the implementation. `OPENSSL_MODULES` is set
 * per child, so each side loads its own provider modules.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define READ_CAP 32768
#define CELL_TIMEOUT_MS 25000

struct capture {
    char buf[READ_CAP];
    size_t len;
};

static void append(struct capture *c, const char *p, size_t n)
{
    if (c->len + n > sizeof c->buf - 1)
        n = sizeof c->buf - 1 - c->len;
    memcpy(c->buf + c->len, p, n);
    c->len += n;
    c->buf[c->len] = '\0';
}

static pid_t spawn(const char *path, const char *role, int fd, const char *cert,
                   const char *key, const char *modules, int wfd)
{
    pid_t p = fork();

    if (p == 0) {
        char fdbuf[16];
        int i;

        dup2(fd, 3);
        dup2(wfd, 1);
        dup2(wfd, 2);
        for (i = 3; i <= 64; i++) {
            if (i != 3)
                close(i);
        }
        /* The rpath on the peer selects the implementation; a shared LD_LIBRARY_PATH would
           override it and load one side's libssl into the other's process. */
        unsetenv("LD_LIBRARY_PATH");
        setenv("OPENSSL_CONF", "/dev/null", 1);
        if (modules != NULL && modules[0] != '\0')
            setenv("OPENSSL_MODULES", modules, 1);
        snprintf(fdbuf, sizeof fdbuf, "3");
        execl(path, path, role, fdbuf, cert, key, (char *)NULL);
        _exit(127);
    }
    return p;
}

static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int run_cell(const char *name, const char *client_peer, const char *client_modules,
                    const char *server_peer, const char *server_modules, const char *cert,
                    const char *key)
{
    int sv[2];
    int cpipe[2], spipe[2];
    pid_t cp, sp;
    struct capture cc, sc;
    struct pollfd fds[2];
    long long deadline;
    int timed_out = 0;
    int cstatus = 0, sstatus = 0;

    memset(&cc, 0, sizeof cc);
    memset(&sc, 0, sizeof sc);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("cell=%s.status=no-socketpair\n", name);
        return 0;
    }
    if (pipe(cpipe) != 0 || pipe(spipe) != 0) {
        printf("cell=%s.status=no-pipe\n", name);
        return 0;
    }

    fflush(stdout);
    cp = spawn(client_peer, "client", sv[0], cert, key, client_modules, cpipe[1]);
    sp = spawn(server_peer, "server", sv[1], cert, key, server_modules, spipe[1]);

    close(sv[0]);
    close(sv[1]);
    close(cpipe[1]);
    close(spipe[1]);

    fds[0].fd = cpipe[0];
    fds[0].events = POLLIN;
    fds[1].fd = spipe[0];
    fds[1].events = POLLIN;

    deadline = now_ms() + CELL_TIMEOUT_MS;
    for (;;) {
        int r, i;

        if (fds[0].fd < 0 && fds[1].fd < 0)
            break;
        r = poll(fds, 2, 500);
        if (now_ms() > deadline) {
            timed_out = 1; /* timeout */
            break;
        }
        if (r < 0)
            break;
        for (i = 0; i < 2; i++) {
            if (fds[i].fd < 0 || fds[i].revents == 0)
                continue;
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                char tmp[4096];
                ssize_t n = read(fds[i].fd, tmp, sizeof tmp);

                if (n > 0)
                    append(i == 0 ? &cc : &sc, tmp, (size_t)n);
                else {
                    close(fds[i].fd);
                    fds[i].fd = -1;
                }
            }
        }
    }
    if (fds[0].fd >= 0)
        close(fds[0].fd);
    if (fds[1].fd >= 0)
        close(fds[1].fd);

    if (timed_out) {
        kill(cp, SIGKILL);
        kill(sp, SIGKILL);
    }
    waitpid(cp, &cstatus, 0);
    waitpid(sp, &sstatus, 0);

    /* Re-emit each peer's `key=value` transcript under a stable per-cell prefix. */
    {
        struct capture *caps[2] = { &cc, &sc };
        const char *sides[2] = { "client", "server" };
        int s;

        printf("cell=%s\n", name);
        for (s = 0; s < 2; s++) {
            char *save = NULL;
            char *line = strtok_r(caps[s]->buf, "\n", &save);

            while (line != NULL) {
                if (strchr(line, '=') != NULL)
                    printf("cell=%s.%s.%s\n", name, sides[s], line);
                line = strtok_r(NULL, "\n", &save);
            }
        }
    }
    printf("cell=%s.status=%s\n", name, timed_out ? "timeout" : "complete");
    printf("cell=%s.client.exit=%d\n", name,
           WIFEXITED(cstatus) ? WEXITSTATUS(cstatus) : -1);
    printf("cell=%s.client.signal=%d\n", name,
           WIFSIGNALED(cstatus) ? WTERMSIG(cstatus) : 0);
    printf("cell=%s.server.exit=%d\n", name,
           WIFEXITED(sstatus) ? WEXITSTATUS(sstatus) : -1);
    printf("cell=%s.server.signal=%d\n", name,
           WIFSIGNALED(sstatus) ? WTERMSIG(sstatus) : 0);
    return 0;
}

int main(int argc, char **argv)
{
    char cert[1024], key[1024];
    const char *auth_peer, *auth_modules, *cand_peer, *cand_modules, *fixtures;

    if (argc < 6) {
        fprintf(stderr,
                "usage: %s <authority-peer> <authority-modules> <candidate-peer> "
                "<candidate-modules> <fixtures-dir>\n",
                argv[0]);
        return 2;
    }
    auth_peer = argv[1];
    auth_modules = argv[2];
    cand_peer = argv[3];
    cand_modules = argv[4];
    fixtures = argv[5];
    snprintf(cert, sizeof cert, "%s/signer.pem", fixtures);
    snprintf(key, sizeof key, "%s/rsa-key.pem", fixtures);

    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("matrix.cells=4\n");
    run_cell("auth-auth", auth_peer, auth_modules, auth_peer, auth_modules, cert, key);
    run_cell("cand-auth", cand_peer, cand_modules, auth_peer, auth_modules, cert, key);
    run_cell("auth-cand", auth_peer, auth_modules, cand_peer, cand_modules, cert, key);
    run_cell("cand-cand", cand_peer, cand_modules, cand_peer, cand_modules, cert, key);
    printf("driver.done=1\n");
    return 0;
}
