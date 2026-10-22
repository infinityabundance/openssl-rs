/*
 * Phase-25 L7 workload for the `libnetconf2` family.
 *
 * libnetconf2's OpenSSL consumer path is its TLS session client (src/session_client_tls.c:
 * SSL_new/SSL_connect/SSL_get_verify_result/SSL_read/SSL_write). This harness runs a minimal
 * NETCONF-over-TLS peer (the subject libssl) on loopback, then calls nc_connect_tls() with the
 * fixture CA. Success requires both the TLS handshake and the NETCONF <hello> exchange. The
 * negative control repeats the connection against a server certificate signed by an unrelated
 * CA while the client trusts only the fixture CA: nc_connect_tls must return no session.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <libyang/libyang.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "session.h"
#include "session_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char SERVER_HELLO[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
    "<capabilities><capability>urn:ietf:params:netconf:base:1.0</capability>"
    "</capabilities><session-id>1</session-id></hello>]]>]]>";

struct server {
    int listen_fd;
    int conn_fd;
    const char *cert;
    const char *key;
    int handshake;
    int hello_seen;
    int accepted;
};

static void *server_thread(void *arg)
{
    struct server *s = arg;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    struct timeval tv = { 5, 0 };
    char buf[4096];
    size_t used = 0;
    int n;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        goto out;
    if (SSL_CTX_use_certificate_file(ctx, s->cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, s->key, SSL_FILETYPE_PEM) != 1)
        goto out;

    s->conn_fd = accept(s->listen_fd, NULL, NULL);
    if (s->conn_fd < 0)
        goto out;
    setsockopt(s->conn_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s->conn_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    ssl = SSL_new(ctx);
    if (!ssl)
        goto out;
    SSL_set_fd(ssl, s->conn_fd);
    if (SSL_accept(ssl) != 1) {
        ERR_clear_error();
        goto out;
    }
    s->handshake = 1;

    while (used < sizeof(buf) - 1) {
        n = SSL_read(ssl, buf + used, (int)(sizeof(buf) - 1 - used));
        if (n <= 0)
            break;
        used += (size_t)n;
        buf[used] = '\0';
        if (strstr(buf, "]]>]]>") != NULL) {
            s->hello_seen = 1;
            break;
        }
    }
    if (s->hello_seen) {
        n = SSL_write(ssl, SERVER_HELLO, (int)(sizeof(SERVER_HELLO) - 1));
        s->accepted = (n == (int)(sizeof(SERVER_HELLO) - 1));
    }

out:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (s->conn_fd >= 0)
        close(s->conn_fd);
    if (ctx)
        SSL_CTX_free(ctx);
    ERR_clear_error();
    return NULL;
}

static int listen_loopback(struct server *s)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int one = 1;

    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listen_fd < 0)
        return -1;
    setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s->listen_fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(s->listen_fd, 1) != 0 ||
        getsockname(s->listen_fd, (struct sockaddr *)&a, &alen) != 0)
        return -1;
    return ntohs(a.sin_port);
}

static int connect_once(const char *cert, const char *key, const char *ca,
                        const char *client_cert, const char *client_key, const char *modules,
                        const char *nc_modules)
{
    struct server s;
    struct ly_ctx *ctx = NULL;
    struct nc_session *session = NULL;
    pthread_t th;
    int port, ok = 0;

    memset(&s, 0, sizeof(s));
    s.cert = cert;
    s.key = key;
    s.listen_fd = -1;
    s.conn_fd = -1;
    port = listen_loopback(&s);
    if (port <= 0)
        return 0;
    if (pthread_create(&th, NULL, server_thread, &s) != 0) {
        close(s.listen_fd);
        return 0;
    }

    nc_client_tls_set_cert_key_paths(client_cert, client_key);
    nc_client_tls_set_trusted_ca_paths(ca, NULL);
    {
        int rc = ly_ctx_new(modules, 0, &ctx);
        if (rc == 0)
            rc = ly_ctx_set_searchdir(ctx, nc_modules);
        if (rc == 0)
            session = nc_connect_tls("127.0.0.1", (uint16_t)port, ctx);
    }

    pthread_join(th, NULL);
    if (session) {
        nc_session_free(session, NULL);
        ok = 1;
    }
    if (s.listen_fd >= 0)
        close(s.listen_fd);
    if (ctx)
        ly_ctx_destroy(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL, *other_cert = NULL;
    const char *other_key = NULL;
    const char *client_cert = NULL, *client_key = NULL, *modules = NULL, *nc_modules = NULL;
    int good, bad;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("libnetconf2-l7-harness 1\n");
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc)
            cert = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key = argv[++i];
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc)
            ca = argv[++i];
        else if (strcmp(argv[i], "--other-cert") == 0 && i + 1 < argc)
            other_cert = argv[++i];
        else if (strcmp(argv[i], "--other-key") == 0 && i + 1 < argc)
            other_key = argv[++i];
        else if (strcmp(argv[i], "--client-cert") == 0 && i + 1 < argc)
            client_cert = argv[++i];
        else if (strcmp(argv[i], "--client-key") == 0 && i + 1 < argc)
            client_key = argv[++i];
        else if (strcmp(argv[i], "--modules") == 0 && i + 1 < argc)
            modules = argv[++i];
        else if (strcmp(argv[i], "--nc-modules") == 0 && i + 1 < argc)
            nc_modules = argv[++i];
        else {
            fprintf(stderr, "usage: %s --cert FILE --key FILE --ca FILE --other-cert FILE "
                    "--other-key FILE --client-cert FILE --client-key FILE --modules DIR\n",
                    argv[0]);
            return 3;
        }
    }
    if (!cert || !key || !ca || !other_cert || !other_key || !client_cert || !client_key ||
        !modules || !nc_modules) {
        fprintf(stderr, "harness: certificate arguments are required\n");
        return 3;
    }

    nc_client_init();
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    good = connect_once(cert, key, ca, client_cert, client_key, modules, nc_modules);
    printf("tls_session=%s\n", good ? "ok" : "failed");
    printf("netconf_hello=%s\n", good ? "ok" : "failed");

    /* The unrelated-CA server certificate is signed by other-ca; the client trusts only ca. */
    bad = connect_once(other_cert, other_key, ca, client_cert, client_key, modules, nc_modules);
    printf("wrong_ca=%s\n", bad ? "accepted" : "rejected");

    nc_client_destroy();

    if (good && !bad) {
        printf("result=ok\n");
        return 0;
    }
    printf("result=fail\n");
    return 1;
}
