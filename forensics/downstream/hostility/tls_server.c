/*
 * 24.10 hostility probe (server side): a minimal **TLS server** built against the subject's libssl,
 * used by the section-63 cross-implementation network matrix — a client under one subject talks to a
 * server under the other, in both directions, over loopback only.
 *
 * argv: <port> <cert.pem> <key.pem> <minver> <maxver>
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static int make_listener(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        printf("surface=tls-server\nresult=failed\nreason=usage\n");
        return 1;
    }
    int port = atoi(argv[1]);
    const char *cert = argv[2];
    const char *key = argv[3];
    int minv = argc > 4 ? atoi(argv[4]) : 0;
    int maxv = argc > 5 ? atoi(argv[5]) : 0;

    hostility_banner("tls-server");
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        hostility_fail("SSL_CTX_new");
    if (minv != 0 && !SSL_CTX_set_min_proto_version(ctx, minv))
        hostility_fail("SSL_CTX_set_min_proto_version");
    if (maxv != 0 && !SSL_CTX_set_max_proto_version(ctx, maxv))
        hostility_fail("SSL_CTX_set_max_proto_version");
    if (!SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM))
        hostility_fail("SSL_CTX_use_certificate_file");
    if (!SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM))
        hostility_fail("SSL_CTX_use_PrivateKey_file");
    if (!SSL_CTX_check_private_key(ctx))
        hostility_fail("SSL_CTX_check_private_key");

    int lfd = make_listener(port);
    if (lfd < 0)
        hostility_fail("listen");
    printf("listening=1\n");
    fflush(stdout);

    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0)
        hostility_fail("accept");
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL || !SSL_set_fd(ssl, cfd))
        hostility_fail("SSL_set_fd");
    if (SSL_accept(ssl) != 1) {
        printf("handshake=0\n");
        hostility_fail("SSL_accept");
    }
    printf("handshake=1\n");
    printf("tls_version=%s\n", SSL_get_version(ssl));
    const SSL_CIPHER *ci = SSL_get_current_cipher(ssl);
    printf("cipher=%s\n", ci != NULL ? SSL_CIPHER_get_name(ci) : "(null)");

    char buf[512];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    printf("request_bytes=%d\n", n > 0 ? n : 0);

    const char *resp = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
    printf("response_bytes=%d\n", SSL_write(ssl, resp, (int)strlen(resp)));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
    close(lfd);
    SSL_CTX_free(ctx);
    hostility_ok();
    return 0;
}
