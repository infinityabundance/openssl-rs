/*
 * Phase-25 L7 workload for the `apr-util` family.
 *
 * apr-util ships no TLS client of its own: httpd obtains TLS through libssl
 * while using apr-util for the surrounding runtime, and apr-util's digest
 * helpers are its own public crypto surface. This program therefore:
 *
 *   1. computes apr-util's MD5 digest vector for "abc" and requires the
 *      well-known value, and requires the digest of the mutated input "abd"
 *      to differ (a mutated-digest control);
 *   2. as an apr-util/librt consumer, opens a loopback TCP connection with
 *      apr_socket and completes a real TLS handshake over it with libssl,
 *      verifying the peer against the fixture CA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <apr.h>
#include <apr_errno.h>
#include <apr_general.h>
#include <apr_md5.h>
#include <apr_network_io.h>
#include <apr_pools.h>
#include <apr_portable.h>
#include <apr_strings.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void to_hex(const unsigned char *in, size_t len, char *out)
{
    size_t i;

    for (i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", in[i]);
    out[len * 2] = '\0';
}

static int tls_handshake(apr_pool_t *pool, const char *ca, int port)
{
    apr_sockaddr_t *sa = NULL;
    apr_socket_t *sock = NULL;
    apr_os_sock_t fd;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int rc = -1;

    if (apr_sockaddr_info_get(&sa, "127.0.0.1", APR_INET, (apr_port_t)port, 0, pool) !=
        APR_SUCCESS)
        goto out;
    if (apr_socket_create(&sock, sa->family, SOCK_STREAM, APR_PROTO_TCP, pool) != APR_SUCCESS)
        goto out;
    if (apr_socket_connect(sock, sa) != APR_SUCCESS)
        goto out;
    if (apr_os_sock_get(&fd, sock) != APR_SUCCESS)
        goto out;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto out;
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1)
        goto out;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    ssl = SSL_new(ctx);
    if (ssl == NULL || SSL_set_fd(ssl, (int)fd) != 1)
        goto out;
    if (SSL_connect(ssl) != 1)
        goto out;
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        goto out;
    rc = 0;
 out:
    if (ssl != NULL)
        SSL_free(ssl);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (sock != NULL)
        apr_socket_close(sock);
    return rc;
}

int main(int argc, char **argv)
{
    apr_pool_t *pool = NULL;
    apr_status_t rv;
    unsigned char d1[APR_MD5_DIGESTSIZE], d2[APR_MD5_DIGESTSIZE];
    char hex[APR_MD5_DIGESTSIZE * 2 + 1];
    const char *ca = NULL;
    int port = 0, i, rc = 1;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("apr-util-l7-harness (apr-util)\n");
        return 0;
    }
    for (i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--ca") == 0)
            ca = argv[++i];
        else if (strcmp(argv[i], "--port") == 0)
            port = atoi(argv[++i]);
    }
    if (ca == NULL || port <= 0) {
        fprintf(stderr, "usage: %s --ca <ca.pem> --port <port>\n", argv[0]);
        return 2;
    }
    if (apr_initialize() != APR_SUCCESS)
        return 1;
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        return 1;

    apr_md5(d1, "abc", 3);
    apr_md5(d2, "abd", 3);
    to_hex(d1, sizeof(d1), hex);
    if (strcmp(hex, "900150983cd24fb0d6963f7d28e17f72") != 0) {
        fprintf(stderr, "apr-util: the MD5 digest vector did not match (%s)\n", hex);
        goto out;
    }
    if (memcmp(d1, d2, sizeof(d1)) == 0) {
        fprintf(stderr, "apr-util: the mutated digest matched\n");
        goto out;
    }
    printf("digest=ok\nmutated_digest=mismatch\n");

    rv = tls_handshake(pool, ca, port);
    if (rv != 0) {
        fprintf(stderr, "apr-util: the TLS handshake failed\n");
        goto out;
    }
    printf("tls_handshake=ok\npeer_verify=ok\n");
    rc = 0;
 out:
    apr_pool_destroy(pool);
    apr_terminate();
    return rc;
}
