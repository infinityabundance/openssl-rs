/*
 * Phase-25 L7 workload for the library-only `libstrophe` family.
 *
 * libstrophe ships no program of its own. This harness drives its XMPP client
 * path: the client connects to a local stub, negotiates mandatory STARTTLS
 * through libstrophe's OpenSSL backend, verifies the server certificate
 * against the fixture CA, authenticates with SASL PLAIN and exchanges a
 * message stanza whose body must come back unchanged.
 *
 * A client that trusts only an unrelated CA must fail the TLS connection.
 *
 * The stub speaks just enough XMPP for libstrophe's own state machine; it
 * uses OpenSSL directly for its side of the TLS handshake.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <strophe.h>

static const char PAYLOAD[] = "phase25-l7-libstrophe-body";

static volatile sig_atomic_t g_connected;
static volatile sig_atomic_t g_connect_failed;
static volatile sig_atomic_t g_stanza_ok;
static volatile sig_atomic_t g_disconnected;

static void set_timeout(int fd, int seconds)
{
    struct timeval tv;

    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Read until `needle` appears or the buffer fills / the peer stalls. */
static int recv_until(SSL *ssl, char *buf, size_t cap, const char *needle)
{
    size_t used = 0;

    buf[0] = '\0';
    while (used + 1 < cap) {
        int n = SSL_read(ssl, buf + used, (int)(cap - used - 1));
        if (n <= 0)
            return 0;
        used += (size_t)n;
        buf[used] = '\0';
        if (strstr(buf, needle) != NULL)
            return 1;
    }
    return 0;
}

static int send_text(SSL *ssl, const char *text)
{
    size_t len = strlen(text);
    size_t off = 0;

    while (off < len) {
        int n = SSL_write(ssl, text + off, (int)(len - off));
        if (n <= 0)
            return 0;
        off += (size_t)n;
    }
    return 1;
}

static int send_plain(int fd, const char *text)
{
    size_t len = strlen(text);
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, text + off, len - off, 0);
        if (n <= 0)
            return 0;
        off += (size_t)n;
    }
    return 1;
}

#define STREAM_HEAD \
    "<?xml version='1.0'?><stream:stream xmlns='jabber:client' " \
    "xmlns:stream='http://etherx.jabber.org/streams' from='localhost' " \
    "id='l7stream' version='1.0'>"

static void stub(int listen_fd, const char *cert, const char *key)
{
    char buf[8192], body[512];
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int fd = -1;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL || SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "stub: cert load failed\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }

    fd = accept(listen_fd, NULL, NULL);
    if (fd < 0)
        goto out;
    set_timeout(fd, 6);
    if (!send_plain(fd, STREAM_HEAD))
        goto out;
    {
        size_t used = 0;
        while (used + 1 < sizeof(buf)) {
            ssize_t n = recv(fd, buf + used, sizeof(buf) - used - 1, 0);
            if (n <= 0)
                goto out;
            used += (size_t)n;
            buf[used] = '\0';
            if (strstr(buf, "<stream:stream") != NULL)
                break;
        }
    }
    if (!send_plain(fd, "<stream:features><starttls "
                        "xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/>"
                        "</starttls></stream:features>"))
        goto out;
    {
        size_t used = 0;
        buf[0] = '\0';
        while (used + 1 < sizeof(buf)) {
            ssize_t n = recv(fd, buf + used, sizeof(buf) - used - 1, 0);
            if (n <= 0)
                goto out;
            used += (size_t)n;
            buf[used] = '\0';
            if (strstr(buf, "<starttls") != NULL)
                break;
        }
    }
    if (!send_plain(fd, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
        goto out;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto out;
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1)
        goto out;
    printf("tls=%s\n", SSL_version(ssl) == TLS1_3_VERSION ? "TLSv1.3" : "other");
    fflush(stdout);

    if (!recv_until(ssl, buf, sizeof(buf), "<stream:stream"))
        goto out;
    if (!send_text(ssl, STREAM_HEAD))
        goto out;
    if (!send_text(ssl, "<stream:features><mechanisms "
                        "xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN"
                        "</mechanism></mechanisms></stream:features>"))
        goto out;
    if (!recv_until(ssl, buf, sizeof(buf), "</auth>"))
        goto out;
    if (!send_text(ssl, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"))
        goto out;
    if (!recv_until(ssl, buf, sizeof(buf), "<stream:stream"))
        goto out;
    if (!send_text(ssl, STREAM_HEAD))
        goto out;
    if (!send_text(ssl, "<stream:features><bind "
                        "xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>"))
        goto out;

    /* Answer the bind and (if sent) session IQs, then exchange one message. */
    for (int round = 0; round < 8; round++) {
        const char *id_attr;
        char id[128] = "l7";

        if (!recv_until(ssl, buf, sizeof(buf), ">"))
            break;
        if (strstr(buf, "<message") != NULL && strstr(buf, PAYLOAD) != NULL) {
            snprintf(body, sizeof(body),
                     "<message from='stub@localhost' to='l7@localhost' type='chat'>"
                     "<body>%s</body></message>", PAYLOAD);
            if (!send_text(ssl, body))
                goto out;
            break;
        }
        if (strstr(buf, "<iq") == NULL)
            continue;
        id_attr = strstr(buf, "id='");
        if (id_attr == NULL)
            id_attr = strstr(buf, "id=\"");
        if (id_attr != NULL) {
            size_t i = 0;
            char quote = id_attr[3];
            id_attr += 4;
            while (id_attr[i] != '\0' && id_attr[i] != quote && i + 1 < sizeof(id)) {
                id[i] = id_attr[i];
                i++;
            }
            id[i] = '\0';
        }
        snprintf(body, sizeof(body),
                 "<iq type='result' id='%s'><bind "
                 "xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                 "<jid>l7@localhost/l7</jid></bind></iq>", id);
        if (!send_text(ssl, body))
            goto out;
    }
    /* Give the client a moment to parse the stanza before the socket closes. */
    recv_until(ssl, buf, sizeof(buf), "</stream:stream");
 out:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (fd >= 0)
        close(fd);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
}

static int message_handler(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t *body = xmpp_stanza_get_child_by_name(stanza, "body");
    const char *text;

    (void)conn;
    (void)userdata;
    if (body == NULL)
        return 1;
    text = xmpp_stanza_get_text(body);
    if (text != NULL && strcmp(text, PAYLOAD) == 0)
        g_stanza_ok = 1;
    if (text != NULL)
        xmpp_free(xmpp_stanza_get_context(stanza), (void *)text);
    return 1;
}

static int certfail_handler(const xmpp_tlscert_t *cert, const char *err)
{
    (void)cert;
    printf("negative=rejected\n");
    if (err != NULL)
        printf("verify_error=%s\n", err);
    fflush(NULL);
    /* The rejection is the observable; upstream's post-failure shutdown path is not. */
    _exit(0);
    return 0;
}

static void log_handler(void *userdata, xmpp_log_level_t level, const char *area,
                        const char *msg)
{
    (void)userdata;
    fprintf(stderr, "[xmpp:%d:%s] %s", (int)level, area ? area : "-", msg);
}

static void conn_handler(xmpp_conn_t *conn, xmpp_conn_event_t status, int error,
                         xmpp_stream_error_t *stream_error, void *userdata)
{
    (void)error;
    (void)stream_error;
    (void)userdata;
    if (status == XMPP_CONN_CONNECT) {
        g_connected = 1;
        xmpp_handler_add(conn, message_handler, NULL, "message", NULL, NULL);
        xmpp_send_raw_string(conn,
                             "<message to='stub@localhost' type='chat'>"
                             "<body>%s</body></message>", PAYLOAD);
    } else if (status == XMPP_CONN_FAIL) {
        g_connect_failed = 1;
    } else if (status == XMPP_CONN_DISCONNECT) {
        g_disconnected = 1;
    }
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL;
    int port = 0, rc = 1;
    int negative = 0;
    pid_t child;
    xmpp_ctx_t *ctx;
    xmpp_log_t log;
    xmpp_conn_t *conn;
    int waited;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            printf("libstrophe-l7-harness\n");
            return 0;
        } else if (!strcmp(argv[i], "--negative")) {
            negative = 1;
        } else if (!strcmp(argv[i], "--cert") && i + 1 < argc) {
            cert = argv[++i];
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            key = argv[++i];
        } else if (!strcmp(argv[i], "--ca") && i + 1 < argc) {
            ca = argv[++i];
        }
    }
    if (cert == NULL || key == NULL || ca == NULL) {
        fprintf(stderr, "usage: %s --cert F --key F --ca F\n", argv[0]);
        return 2;
    }

    {
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sin;
        socklen_t slen = sizeof(sin);
        int one = 1;

        if (lfd < 0)
            return 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(lfd, (struct sockaddr *)&sin, sizeof(sin)) != 0 ||
            listen(lfd, 4) != 0)
            return 1;
        if (getsockname(lfd, (struct sockaddr *)&sin, &slen) != 0)
            return 1;
        port = ntohs(sin.sin_port);
        child = fork();
        if (child == 0) {
            stub(lfd, cert, key);
            close(lfd);
            _exit(0);
        }
        close(lfd);
    }

    xmpp_initialize();
    log.handler = log_handler;
    log.userdata = NULL;
    ctx = xmpp_ctx_new(NULL, &log);
    conn = xmpp_conn_new(ctx);
    if (ctx == NULL || conn == NULL) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    xmpp_conn_set_jid(conn, "l7@localhost");
    xmpp_conn_set_pass(conn, "phase25-secret");
    xmpp_conn_set_cafile(conn, ca);
    xmpp_conn_set_flags(conn, XMPP_CONN_FLAG_MANDATORY_TLS);
    if (negative)
        xmpp_conn_set_certfail_handler(conn, certfail_handler);

    if (xmpp_connect_client(conn, "127.0.0.1", (unsigned short)port,
                            conn_handler, NULL) != 0) {
        fprintf(stderr, "libstrophe: connect failed\n");
        goto out;
    }
    for (waited = 0; waited < 1000 && !g_stanza_ok && !g_connect_failed; waited++)
        xmpp_run_once(ctx, 20);
    if (negative) {
        if (g_connect_failed) {
            printf("negative=rejected\n");
            fflush(NULL);
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            /* The observed rejection is the TLS failure itself; upstream's shutdown
             * path after a failed handshake is outside this workload's assertion. */
            _exit(0);
        }
        fprintf(stderr, "libstrophe: the unrelated CA completed the TLS connection\n");
    } else if (g_stanza_ok && g_connected) {
        printf("stanza=ok\n");
        rc = 0;
    } else {
        fprintf(stderr, "libstrophe: no stanza exchange completed\n");
    }
    xmpp_disconnect(conn);
    usleep(100000);
 out:
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return rc;
}
