/*
 * Diagnostic TLS client for the Phase 17 downstream/curl slice.
 *
 * Links only the shipped distribution surface (candidate OR authority prefix, chosen by -I/-L
 * and an rpath) and connects to a real, already-running TLS server over a socket. It is not a
 * court; it exists to name the exact stop point when the candidate-linked curl's handshake
 * fails, by printing SSL_get_error and the ERR queue at each SSL_connect step.
 *
 * usage: client_probe <host> <port> <ca.pem|-> (verify|noverify)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

static void dump_errors(const char *tag)
{
    unsigned long e;
    int i = 0;

    while ((e = ERR_get_error()) != 0 && i < 8) {
        char b[256];
        ERR_error_string_n(e, b, sizeof b);
        printf("  %s.err[%d]=%s\n", tag, i, b);
        i++;
    }
    printf("  %s.err.count=%d\n", tag, i);
}

int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 8446;
    const char *ca = argc > 3 ? argv[3] : "-";
    int verify = !(argc > 4 && strcmp(argv[4], "noverify") == 0);
    SSL_CTX *ctx;
    SSL *ssl;
    int fd, r, i;
    struct sockaddr_in a;

    setvbuf(stdout, NULL, _IOLBF, 0);
    OPENSSL_init_ssl(0, NULL);

    ctx = SSL_CTX_new(TLS_client_method());
    printf("ctx.nonnull=%d\n", ctx != NULL);
    if (ctx == NULL) { dump_errors("ctx"); return 1; }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (strcmp(ca, "-") != 0)
            printf("ca.load=%d\n", SSL_CTX_load_verify_locations(ctx, ca, NULL));
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        printf("ca.load=-1\n");
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, host, &a.sin_addr);
    printf("socket.connect=%d\n", connect(fd, (struct sockaddr *)&a, sizeof a));

    ssl = SSL_new(ctx);
    printf("ssl.nonnull=%d\n", ssl != NULL);
    printf("sni=%d\n", SSL_set_tlsext_host_name(ssl, host));
    SSL_set_fd(ssl, fd);

    for (i = 0; i < 6; i++) {
        r = SSL_connect(ssl);
        if (r == 1) {
            printf("ssl_connect[%d]=1\n", i);
            break;
        }
        int err = SSL_get_error(ssl, r);
        printf("ssl_connect[%d]=%d ssl_get_error=%d\n", i, r, err);
        dump_errors("connect");
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
            break;
    }
    printf("handshake.finished=%d\n", SSL_is_init_finished(ssl));
    printf("verify.result=%ld\n", SSL_get_verify_result(ssl));
    printf("version=%s\n", SSL_get_version(ssl));
    printf("cipher=%s\n", SSL_get_cipher_name(ssl));
    dump_errors("final");

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
