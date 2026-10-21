/*
 * Phase-24.7 L7 workload for the library-only `libretls` family.
 *
 * libretls ships no executable of its own, so the admitted workload is this
 * small program: a libtls client and a libtls server exchange one payload over
 * a socketpair. The client configures the fixture CA, completes a TLS 1.3
 * handshake, asserts the peer certificate was provided and verified, and
 * checks the echoed payload. With an unrelated CA the handshake must fail.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <tls.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static const char PAYLOAD[] = "phase24-libretls-l7-payload\n";

static ssize_t wait_io(int fd, short events)
{
    struct pollfd pfd = { fd, events, 0 };

    return poll(&pfd, 1, 20000);
}

static int write_all(struct tls *ctx, int fd, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = tls_write(ctx, buf + off, len - off);

        if (n == TLS_WANT_POLLIN) {
            if (wait_io(fd, POLLIN) <= 0)
                return -1;
        } else if (n == TLS_WANT_POLLOUT) {
            if (wait_io(fd, POLLOUT) <= 0)
                return -1;
        } else if (n <= 0) {
            return -1;
        } else {
            off += (size_t)n;
        }
    }
    return 0;
}

static int read_exact(struct tls *ctx, int fd, char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = tls_read(ctx, buf + off, len - off);

        if (n == TLS_WANT_POLLIN) {
            if (wait_io(fd, POLLIN) <= 0)
                return -1;
        } else if (n == TLS_WANT_POLLOUT) {
            if (wait_io(fd, POLLOUT) <= 0)
                return -1;
        } else if (n <= 0) {
            return -1;
        } else {
            off += (size_t)n;
        }
    }
    return 0;
}

static int server_side(int fd, const char *cert, const char *key)
{
    struct tls_config *cfg = NULL;
    struct tls *sctx = NULL, *conn = NULL;
    char buf[256];
    int rc = 1;

    alarm(20);
    cfg = tls_config_new();
    if (cfg == NULL)
        goto out;
    if (tls_config_set_cert_file(cfg, cert) == -1 ||
        tls_config_set_key_file(cfg, key) == -1 ||
        tls_config_set_protocols(cfg, TLS_PROTOCOL_TLSv1_3) == -1)
        goto out;
    sctx = tls_server();
    if (sctx == NULL || tls_configure(sctx, cfg) == -1)
        goto out;
    if (tls_accept_socket(sctx, &conn, fd) == -1)
        goto out;
    if (tls_handshake(conn) == -1)
        goto out;
    if (read_exact(conn, fd, buf, strlen(PAYLOAD)) == -1)
        goto out;
    if (memcmp(buf, PAYLOAD, strlen(PAYLOAD)) != 0)
        goto out;
    if (write_all(conn, fd, PAYLOAD, strlen(PAYLOAD)) == -1)
        goto out;
    if (tls_close(conn) == -1)
        goto out;
    printf("server=ok\n");
    fflush(stdout);
    rc = 0;
 out:
    if (rc != 0)
        fprintf(stderr, "server: %s\n", sctx != NULL ? tls_error(sctx) : "setup failed");
    if (conn != NULL)
        tls_free(conn);
    if (sctx != NULL)
        tls_free(sctx);
    if (cfg != NULL)
        tls_config_free(cfg);
    return rc;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL;
    struct tls_config *cfg = NULL;
    struct tls *ctx = NULL;
    char buf[256];
    int sv[2], i, negative = 0, status = 0;
    pid_t child;
    const char *version;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("libretls-l7-harness 1\n");
            return 0;
        } else if (strcmp(argv[i], "--negative") == 0) {
            negative = 1;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca = argv[++i];
        } else {
            fprintf(stderr, "usage: %s [--negative] --cert FILE --key FILE --ca FILE\n",
                    argv[0]);
            return 3;
        }
    }
    if (cert == NULL || key == NULL || ca == NULL) {
        fprintf(stderr, "harness: --cert, --key and --ca are required\n");
        return 3;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("socketpair");
        return 1;
    }
    alarm(20);
    child = fork();
    if (child == -1) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        close(sv[0]);
        _exit(server_side(sv[1], cert, key));
    }
    close(sv[1]);

    cfg = tls_config_new();
    if (cfg == NULL)
        goto client_fail;
    if (tls_config_set_ca_file(cfg, ca) == -1 ||
        tls_config_set_protocols(cfg, TLS_PROTOCOL_TLSv1_3) == -1)
        goto client_fail;
    ctx = tls_client();
    if (ctx == NULL || tls_configure(ctx, cfg) == -1)
        goto client_fail;
    if (tls_connect_socket(ctx, sv[0], "127.0.0.1") == -1)
        goto client_fail;
    if (tls_handshake(ctx) == -1)
        goto client_fail;

    version = tls_conn_version(ctx);
    if (negative) {
        printf("harness=libretls-l7\n");
        printf("version=1\n");
        printf("handshake=%s\n", version != NULL ? version : "TLSv1.3");
        printf("peer_verify=accepted\n");
        printf("payload=not-run\n");
        printf("negative=accepted\n");
        printf("result=fail\n");
        fflush(stdout);
        close(sv[0]);
        waitpid(child, &status, 0);
        return 2;
    }
    if (version == NULL || strcmp(version, "TLSv1.3") != 0 ||
        tls_peer_cert_provided(ctx) != 1)
        goto client_fail;
    if (write_all(ctx, sv[0], PAYLOAD, strlen(PAYLOAD)) == -1)
        goto client_fail;
    if (read_exact(ctx, sv[0], buf, strlen(PAYLOAD)) == -1)
        goto client_fail;
    if (memcmp(buf, PAYLOAD, strlen(PAYLOAD)) != 0)
        goto client_fail;
    if (tls_close(ctx) == -1)
        goto client_fail;

    printf("harness=libretls-l7\n");
    printf("version=1\n");
    printf("handshake=%s\n", version);
    printf("peer_verify=ok\n");
    printf("payload=ok\n");
    printf("negative=not-run\n");
    printf("result=ok\n");
    fflush(stdout);
    close(sv[0]);
    waitpid(child, &status, 0);
    return 0;

 client_fail:
    if (negative) {
        const char *err = ctx != NULL ? tls_error(ctx) : NULL;
        int verified = err != NULL &&
            (strstr(err, "certificate verification failed") != NULL ||
             strstr(err, "unable to get local issuer certificate") != NULL);

        printf("harness=libretls-l7\n");
        printf("version=1\n");
        printf("handshake=failed\n");
        printf("peer_verify=failed\n");
        printf("payload=not-run\n");
        printf("negative=%s\n", verified ? "rejected" : "error");
        printf("result=%s\n", verified ? "ok" : "fail");
        if (err != NULL)
            fprintf(stderr, "client: %s\n", err);
        fflush(stdout);
        close(sv[0]);
        waitpid(child, &status, 0);
        return verified ? 0 : 1;
    }
    if (ctx != NULL)
        fprintf(stderr, "client: %s\n", tls_error(ctx));
    close(sv[0]);
    waitpid(child, &status, 0);
    printf("harness=libretls-l7\n");
    printf("version=1\n");
    printf("handshake=failed\n");
    printf("peer_verify=failed\n");
    printf("payload=failed\n");
    printf("negative=not-run\n");
    printf("result=fail\n");
    fflush(stdout);
    return 1;
}
