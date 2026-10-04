/*
 * Diagnostic: does the candidate libssl attach a caller-supplied BIO?
 *
 * curl's OpenSSL backend wraps its connection filter in a custom BIO and hands it to
 * libssl with SSL_set0_rbio()/SSL_set0_wbio() (see HAVE_SSL_SET0_WBIO in
 * lib/vtls/openssl.c). A client that instead uses SSL_set_fd() works against the candidate,
 * so this probe compares the two attachment paths on the same socket.
 *
 * usage: bio_probe <host> <port> <fd|set0>
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
    int port = argc > 2 ? atoi(argv[2]) : 8451;
    int set0 = argc > 3 && strcmp(argv[3], "set0") == 0;
    SSL_CTX *ctx;
    SSL *ssl;
    int fd, r;
    struct sockaddr_in a;

    setvbuf(stdout, NULL, _IOLBF, 0);
    OPENSSL_init_ssl(0, NULL);

    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, host, &a.sin_addr);
    printf("connect=%d\n", connect(fd, (struct sockaddr *)&a, sizeof a));

    ssl = SSL_new(ctx);
    printf("ssl.nonnull=%d\n", ssl != NULL);
    printf("sni=%d\n", SSL_set_tlsext_host_name(ssl, host));

    if (set0) {
        BIO *b = BIO_new_socket(fd, BIO_NOCLOSE);
        printf("bio.nonnull=%d\n", b != NULL);
        printf("bio_up_ref=%d\n", BIO_up_ref(b));
        SSL_set0_rbio(ssl, b);
        SSL_set0_wbio(ssl, b);
        printf("set0_rbio=void\n");
    } else {
        SSL_set_fd(ssl, fd);
    }
    printf("rbio.nonnull=%d\n", SSL_get_rbio(ssl) != NULL);
    printf("wbio.nonnull=%d\n", SSL_get_wbio(ssl) != NULL);

    r = SSL_connect(ssl);
    printf("ssl_connect=%d ssl_get_error=%d\n", r, SSL_get_error(ssl, r));
    dump_errors("connect");
    printf("finished=%d version=%s cipher=%s\n",
           SSL_is_init_finished(ssl), SSL_get_version(ssl), SSL_get_cipher_name(ssl));

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
