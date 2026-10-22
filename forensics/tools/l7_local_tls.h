/*
 * A minimal loopback TLS server shared by the Phase-25 L7 harnesses.
 *
 * It is deliberately small: bind 127.0.0.1:0, load the fixture certificate/key, accept at most
 * `max_conns` connections and run the caller's handler on each. The handler owns the application
 * protocol; this file owns only the listener, the handshake and full-length read/write helpers.
 *
 * This is a test-only instrument under forensics/tools/; it is never linked into src/.
 */
#ifndef L7_LOCAL_TLS_H
#define L7_LOCAL_TLS_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int (*l7_tls_handler)(SSL *ssl, void *arg);

typedef struct {
    SSL_CTX *ctx;
    int listener;
    int port;
    pthread_t thread;
    l7_tls_handler handler;
    void *arg;
    int max_conns;
    int running;
} l7_tls_server;

static inline int l7_read_full(SSL *ssl, void *buf, size_t len)
{
    unsigned char *p = (unsigned char *)buf;
    size_t done = 0;
    while (done < len) {
        int n = SSL_read(ssl, p + done, (int)(len - done));
        if (n <= 0)
            return 0;
        done += (size_t)n;
    }
    return 1;
}

static inline int l7_write_all(SSL *ssl, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t done = 0;
    while (done < len) {
        int n = SSL_write(ssl, p + done, (int)(len - done));
        if (n <= 0)
            return 0;
        done += (size_t)n;
    }
    return 1;
}

static inline int l7_plain_write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n <= 0)
            return 0;
        done += (size_t)n;
    }
    return 1;
}

static inline void *l7_tls_server_main(void *opaque)
{
    l7_tls_server *srv = (l7_tls_server *)opaque;
    int served = 0;

    while (served < srv->max_conns) {
        int fd = accept(srv->listener, NULL, NULL);
        if (fd < 0)
            break;
        served++;
        SSL *ssl = SSL_new(srv->ctx);
        if (ssl != NULL) {
            SSL_set_fd(ssl, fd);
            if (SSL_accept(ssl) == 1) {
                srv->handler(ssl, srv->arg);
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
        }
        close(fd);
    }
    return NULL;
}

/* Start a loopback server; returns 0 on success and fills *out. */
static inline int l7_tls_server_start(l7_tls_server *out, const char *cert, const char *key,
                                      l7_tls_handler handler, void *arg, int max_conns)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int one = 1;

    memset(out, 0, sizeof(*out));
    out->listener = -1;
    out->handler = handler;
    out->arg = arg;
    out->max_conns = max_conns > 0 ? max_conns : 1;

    out->ctx = SSL_CTX_new(TLS_server_method());
    if (out->ctx == NULL)
        return -1;
    SSL_CTX_set_min_proto_version(out->ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_chain_file(out->ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(out->ctx, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(out->ctx) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(out->ctx);
        out->ctx = NULL;
        return -1;
    }

    out->listener = socket(AF_INET, SOCK_STREAM, 0);
    if (out->listener < 0)
        goto fail;
    setsockopt(out->listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(out->listener, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        goto fail;
    if (listen(out->listener, 8) != 0)
        goto fail;
    if (getsockname(out->listener, (struct sockaddr *)&addr, &addrlen) != 0)
        goto fail;
    out->port = ntohs(addr.sin_port);
    if (pthread_create(&out->thread, NULL, l7_tls_server_main, out) != 0)
        goto fail;
    out->running = 1;
    return 0;

fail:
    if (out->listener >= 0)
        close(out->listener);
    out->listener = -1;
    SSL_CTX_free(out->ctx);
    out->ctx = NULL;
    return -1;
}

static inline void l7_tls_server_stop(l7_tls_server *srv)
{
    if (!srv->running)
        return;
    shutdown(srv->listener, SHUT_RDWR);
    close(srv->listener);
    srv->listener = -1;
    pthread_join(srv->thread, NULL);
    srv->running = 0;
    SSL_CTX_free(srv->ctx);
    srv->ctx = NULL;
}

#endif /* L7_LOCAL_TLS_H */
