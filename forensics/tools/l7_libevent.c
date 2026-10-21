/*
 * Phase-24.7 L7 workload for the library-only `libevent` family.
 *
 * libevent ships no executable of its own, so the admitted workload is this
 * small program: two libevent_openssl bufferevents over a socketpair perform a
 * TLS 1.3 handshake, the client verifies the server certificate against the
 * fixture CA, and one encrypted byte round trip must return the payload. A
 * second session with an unrelated CA must fail the handshake.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/util.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char PAYLOAD[] = "phase24-libevent-l7-payload\n";

struct state {
    struct event_base *base;
    struct bufferevent *cli;
    char got[512];
    size_t got_len;
    int connected;
    int verify_ok;
    int tls13;
    int payload_ok;
    int negative;
    int neg_accepted;
    int failed;
    int done;
};

static void finish(struct state *s)
{
    if (!s->done) {
        s->done = 1;
        event_base_loopexit(s->base, NULL);
    }
}

static void srv_read(struct bufferevent *bev, void *arg)
{
    char buf[512];
    size_t n;

    (void)arg;
    while ((n = bufferevent_read(bev, buf, sizeof(buf))) > 0)
        bufferevent_write(bev, buf, n);
}

static void cli_read(struct bufferevent *bev, void *arg)
{
    struct state *s = arg;
    size_t n, want = strlen(PAYLOAD);

    while (s->got_len < sizeof(s->got) - 1 &&
           (n = bufferevent_read(bev, s->got + s->got_len,
                                 sizeof(s->got) - 1 - s->got_len)) > 0) {
        s->got_len += n;
        if (s->got_len >= want)
            break;
    }
    s->got[s->got_len] = '\0';
    if (s->got_len >= want) {
        s->payload_ok = (s->got_len == want &&
                         memcmp(s->got, PAYLOAD, want) == 0);
        if (!s->payload_ok)
            s->failed = 1;
        finish(s);
    }
}

static void cli_event(struct bufferevent *bev, short events, void *arg)
{
    struct state *s = arg;

    if (events & BEV_EVENT_CONNECTED) {
        SSL *ssl;

        if (s->negative) {
            s->neg_accepted = 1;
            finish(s);
            return;
        }
        ssl = bufferevent_openssl_get_ssl(bev);
        s->connected = 1;
        s->tls13 = ssl != NULL && SSL_version(ssl) == TLS1_3_VERSION;
        if (ssl != NULL) {
            X509 *peer = SSL_get1_peer_certificate(ssl);

            s->verify_ok = (SSL_get_verify_result(ssl) == X509_V_OK && peer != NULL);
            X509_free(peer);
        }
        if (!s->tls13 || !s->verify_ok) {
            s->failed = 1;
            finish(s);
            return;
        }
        bufferevent_write(bev, PAYLOAD, strlen(PAYLOAD));
        return;
    }
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF | BEV_EVENT_TIMEOUT)) {
        if (s->negative) {
            /* The server certificate does not chain to the configured CA. */
            finish(s);
            return;
        }
        s->failed = 1;
        finish(s);
    }
}

static SSL_CTX *make_ctx(int server, const char *cert, const char *key, const char *ca)
{
    SSL_CTX *ctx;
    const SSL_METHOD *method = server ? TLS_server_method() : TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
        return NULL;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (server) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL;
    struct state st;
    struct event_base *base;
    struct bufferevent *srv = NULL;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *ssl_srv = NULL, *ssl_cli = NULL;
    struct timeval tv = { 20, 0 };
    int sv[2], i, negative = 0, rc;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("libevent-l7-harness 1\n");
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
    /* libevent's bufferevent performs SSL_do_handshake from the event loop; a blocking fd would
     * stall the same loop that has to drive the peer. */
    if (evutil_make_socket_nonblocking(sv[0]) != 0 ||
        evutil_make_socket_nonblocking(sv[1]) != 0) {
        perror("evutil_make_socket_nonblocking");
        return 1;
    }

    memset(&st, 0, sizeof(st));
    st.negative = negative;
    base = event_base_new();
    if (base == NULL) {
        fprintf(stderr, "harness: event_base_new failed\n");
        return 1;
    }
    st.base = base;
    sctx = make_ctx(1, cert, key, NULL);
    cctx = make_ctx(0, NULL, NULL, ca);
    if (sctx == NULL || cctx == NULL) {
        fprintf(stderr, "harness: SSL_CTX setup failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    ssl_srv = SSL_new(sctx);
    ssl_cli = SSL_new(cctx);
    if (ssl_srv == NULL || ssl_cli == NULL) {
        fprintf(stderr, "harness: SSL_new failed\n");
        return 1;
    }
    SSL_set_accept_state(ssl_srv);
    SSL_set_connect_state(ssl_cli);

    srv = bufferevent_openssl_socket_new(base, sv[0], ssl_srv,
                                         BUFFEREVENT_SSL_ACCEPTING,
                                         BEV_OPT_CLOSE_ON_FREE);
    st.cli = bufferevent_openssl_socket_new(base, sv[1], ssl_cli,
                                            BUFFEREVENT_SSL_CONNECTING,
                                            BEV_OPT_CLOSE_ON_FREE);
    if (srv == NULL || st.cli == NULL) {
        fprintf(stderr, "harness: bufferevent_openssl_socket_new failed\n");
        return 1;
    }
    bufferevent_setcb(srv, srv_read, NULL, NULL, NULL);
    bufferevent_setcb(st.cli, cli_read, NULL, cli_event, &st);
    bufferevent_enable(srv, EV_READ | EV_WRITE);
    bufferevent_enable(st.cli, EV_READ | EV_WRITE);

    event_base_loopexit(base, &tv);
    event_base_dispatch(base);

    printf("harness=libevent-l7\n");
    printf("version=1\n");
    printf("handshake=%s\n",
           st.negative ? (st.neg_accepted ? "accepted" : "failed") :
           (st.tls13 ? "TLSv1.3" : "none"));
    printf("peer_verify=%s\n", st.verify_ok ? "ok" : "failed");
    printf("payload=%s\n", st.payload_ok ? "ok" : "failed");
    if (st.negative)
        printf("negative=%s\n", st.neg_accepted ? "accepted" : "rejected");
    else
        printf("negative=not-run\n");

    if (st.negative) {
        rc = st.neg_accepted ? 2 : 0;
        printf("result=%s\n", st.neg_accepted ? "fail" : "ok");
    } else if (st.tls13 && st.verify_ok && st.payload_ok) {
        rc = 0;
        printf("result=ok\n");
    } else {
        rc = 1;
        printf("result=fail\n");
    }
    fflush(stdout);
    if (st.cli != NULL)
        bufferevent_free(st.cli);
    if (srv != NULL)
        bufferevent_free(srv);
    event_base_free(base);
    return rc;
}
