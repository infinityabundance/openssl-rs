/*
 * 24.10 hostility probe (client side): a minimal **TLS client** built against the subject's libssl,
 * used by the section-63 cross-implementation network matrix. It verifies the peer against the PKI's
 * CA file (a verified fetch), which is the functional effect the workload exists to prove.
 *
 * argv: <port> <ca.pem> <minver> <maxver>
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static int connect_to(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short)port);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("surface=tls-client\nresult=failed\nreason=usage\n");
        return 1;
    }
    int port = atoi(argv[1]);
    const char *ca = argv[2];
    int minv = argc > 3 ? atoi(argv[3]) : 0;
    int maxv = argc > 4 ? atoi(argv[4]) : 0;

    hostility_banner("tls-client");
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        hostility_fail("SSL_CTX_new");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (minv != 0 && !SSL_CTX_set_min_proto_version(ctx, minv))
        hostility_fail("SSL_CTX_set_min_proto_version");
    if (maxv != 0 && !SSL_CTX_set_max_proto_version(ctx, maxv))
        hostility_fail("SSL_CTX_set_max_proto_version");
    if (!SSL_CTX_load_verify_locations(ctx, ca, NULL))
        hostility_fail("SSL_CTX_load_verify_locations");

    int fd = connect_to(port);
    if (fd < 0)
        hostility_fail("connect");
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        hostility_fail("SSL_new");
    SSL_set_tlsext_host_name(ssl, "127.0.0.1");
    if (!SSL_set_fd(ssl, fd))
        hostility_fail("SSL_set_fd");
    if (SSL_connect(ssl) != 1) {
        printf("handshake=0\n");
        hostility_fail("SSL_connect");
    }
    printf("handshake=1\n");
    printf("tls_version=%s\n", SSL_get_version(ssl));
    const SSL_CIPHER *ci = SSL_get_current_cipher(ssl);
    printf("cipher=%s\n", ci != NULL ? SSL_CIPHER_get_name(ci) : "(null)");
    long vr = SSL_get_verify_result(ssl);
    printf("verify_ok=%d\n", vr == X509_V_OK);

    const char *req = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    SSL_write(ssl, req, (int)strlen(req));
    char buf[2048];
    int total = 0;
    for (;;) {
        int n = SSL_read(ssl, buf + total, (int)sizeof(buf) - 1 - total);
        if (n <= 0)
            break;
        total += n;
        if (total >= (int)sizeof(buf) - 1)
            break;
    }
    buf[total] = '\0';
    printf("response_bytes=%d\n", total);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);

    if (vr != X509_V_OK) {
        printf("http200=0\n");
        hostility_fail("peer verification failed");
    }
    if (strstr(buf, " 200 ") == NULL) {
        printf("http200=0\n");
        hostility_fail("no HTTP 200 in the response");
    }
    printf("http200=1\n");
    hostility_ok();
    return 0;
}
