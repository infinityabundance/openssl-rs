/*
 * Phase-25 L7 workload for the library-only `libwebsockets` family.
 *
 * libwebsockets ships no program of its own. This harness runs a secure
 * WebSocket (wss) server and client on loopback in one process: the client
 * verifies the server certificate against the fixture CA, completes the TLS
 * handshake, sends a payload and must receive the server's echo unchanged.
 *
 * A second client that trusts only an unrelated CA must fail the TLS handshake
 * and never reach the established state.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <libwebsockets.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char PAYLOAD[] = "phase25-l7-libwebsockets-echo";
#define MAX_PAYLOAD 512

struct shim {
    char data[MAX_PAYLOAD];
    size_t len;
};

static int established;
static int echo_ok;
static int failed;

static int free_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    int one = 1;
    int port;

    if (fd < 0)
        return 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0 ||
        listen(fd, 1) != 0) {
        close(fd);
        return 0;
    }
    if (getsockname(fd, (struct sockaddr *)&sin, &slen) != 0) {
        close(fd);
        return 0;
    }
    port = ntohs(sin.sin_port);
    close(fd);
    return port;
}

static int server_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
                     void *in, size_t len)
{
    (void)user;
    switch (reason) {
    case LWS_CALLBACK_RECEIVE: {
        unsigned char buf[LWS_PRE + MAX_PAYLOAD];
        if (len > MAX_PAYLOAD)
            return -1;
        memcpy(buf + LWS_PRE, in, len);
        lws_write(wsi, buf + LWS_PRE, len, LWS_WRITE_TEXT);
        return 0;
    }
    case LWS_CALLBACK_ESTABLISHED:
        established = 1;
        return 0;
    default:
        return 0;
    }
}

static int client_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
                     void *in, size_t len)
{
    struct shim *s = user;

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED: {
        unsigned char buf[LWS_PRE + MAX_PAYLOAD];
        SSL *ssl = lws_get_ssl(wsi);

        if (ssl == NULL) {
            failed = 1;
            lws_cancel_service(lws_get_context(wsi));
            return -1;
        }
        if (SSL_version(ssl) != TLS1_3_VERSION) {
            failed = 1;
            lws_cancel_service(lws_get_context(wsi));
            return -1;
        }
        memcpy(buf + LWS_PRE, PAYLOAD, strlen(PAYLOAD));
        if (lws_write(wsi, buf + LWS_PRE, strlen(PAYLOAD), LWS_WRITE_TEXT) < 0) {
            failed = 1;
            return -1;
        }
        return 0;
    }
    case LWS_CALLBACK_CLIENT_RECEIVE:
        if (s != NULL && s->len + len < MAX_PAYLOAD) {
            memcpy(s->data + s->len, in, len);
            s->len += len;
            if (s->len == strlen(PAYLOAD) &&
                memcmp(s->data, PAYLOAD, strlen(PAYLOAD)) == 0)
                echo_ok = 1;
        }
        return 0;
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        failed = 1;
        return 0;
    case LWS_CALLBACK_CLIENT_CLOSED:
        return 0;
    default:
        return 0;
    }
}

static const struct lws_protocols protocols[] = {
    { "l7-echo", server_cb, 0, MAX_PAYLOAD, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

/* The client uses the same protocol table; its callback is installed per-client below. */
static struct lws_protocols client_protocols[] = {
    { "l7-echo", client_cb, sizeof(struct shim), MAX_PAYLOAD, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

static struct lws_context *make_context(const char *cert, const char *key,
                                        const char *ca, int port,
                                        struct lws_protocols *protos)
{
    struct lws_context_creation_info info;

    memset(&info, 0, sizeof(info));
    info.port = port;
    info.protocols = protos;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    if (cert != NULL) {
        info.ssl_cert_filepath = cert;
        info.ssl_private_key_filepath = key;
    }
    if (ca != NULL)
        info.client_ssl_ca_filepath = ca;
    return lws_create_context(&info);
}

static int run_client(struct lws_context *cctx, struct lws_context *sctx, int port)
{
    struct lws_client_connect_info ccinfo;
    struct lws *wsi = NULL;
    struct shim *shim = NULL;
    int waited = 0;

    memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = cctx;
    ccinfo.address = "127.0.0.1";
    ccinfo.port = port;
    ccinfo.path = "/l7";
    ccinfo.host = "127.0.0.1";
    ccinfo.origin = "https://127.0.0.1";
    ccinfo.protocol = "l7-echo";
    ccinfo.pwsi = &wsi;
    ccinfo.ssl_connection = LCCSCF_USE_SSL;
    ccinfo.alpn = "http/1.1";
    if (lws_client_connect_via_info(&ccinfo) == NULL)
        return -1;
    while (waited < 8000 && !failed && !echo_ok) {
        lws_service(sctx, 0);
        lws_service(cctx, 0);
        usleep(1000);
        waited++;
    }
    (void)shim;
    return echo_ok ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL, *other_ca = NULL;
    int port;
    int negative = 0;
    struct lws_context *sctx = NULL, *cctx = NULL;
    struct lws *wsi = NULL;
    int rc = 1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            printf("libwebsockets-l7-harness\n");
            return 0;
        } else if (!strcmp(argv[i], "--negative")) {
            negative = 1;
        } else if (!strcmp(argv[i], "--cert") && i + 1 < argc) {
            cert = argv[++i];
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            key = argv[++i];
        } else if (!strcmp(argv[i], "--ca") && i + 1 < argc) {
            ca = argv[++i];
        } else if (!strcmp(argv[i], "--other-ca") && i + 1 < argc) {
            other_ca = argv[++i];
        }
    }
    if (cert == NULL || key == NULL || ca == NULL) {
        fprintf(stderr, "usage: %s --cert F --key F --ca F [--other-ca F]\n", argv[0]);
        return 2;
    }
    lws_set_log_level(0, NULL);

    port = free_port();
    if (port <= 0)
        return 1;
    sctx = make_context(cert, key, NULL, port, (struct lws_protocols *)protocols);
    if (sctx == NULL)
        goto done;
    cctx = make_context(NULL, NULL, ca, CONTEXT_PORT_NO_LISTEN,
                        (struct lws_protocols *)client_protocols);
    if (cctx == NULL)
        goto done;

    if (run_client(cctx, sctx, port) != 0 || !established) {
        fprintf(stderr, "libwebsockets: verified wss handshake or echo failed\n");
        goto done;
    }
    lws_context_destroy(cctx);
    cctx = NULL;
    printf("handshake=TLSv1.3\n");
    printf("echo=ok\n");

    if (!negative) {
        rc = 0;
        goto done;
    }
    if (other_ca == NULL) {
        fprintf(stderr, "libwebsockets: --other-ca is required for the negative control\n");
        goto done;
    }
    failed = 0;
    echo_ok = 0;
    cctx = make_context(NULL, NULL, other_ca, CONTEXT_PORT_NO_LISTEN,
                        (struct lws_protocols *)client_protocols);
    if (cctx == NULL)
        goto done;
    wsi = NULL;
    (void)wsi;
    /* A fresh connection attempt: run_client reports success only if it echoes. */
    if (run_client(cctx, sctx, port) == 0) {
        fprintf(stderr, "libwebsockets: the unrelated CA completed the handshake\n");
        goto done;
    }
    if (!failed) {
        fprintf(stderr, "libwebsockets: the negative client did not report a connection error\n");
        goto done;
    }
    printf("negative=rejected\n");
    rc = 0;
 done:
    if (cctx != NULL)
        lws_context_destroy(cctx);
    if (sctx != NULL)
        lws_context_destroy(sctx);
    return rc;
}
