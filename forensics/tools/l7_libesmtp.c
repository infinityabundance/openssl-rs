/*
 * Phase-25 L7 workload for the library-only `libesmtp` family.
 *
 * libesmtp ships no program of its own. This harness submits one message to a
 * local SMTP stub: libesmtp's STARTTLS path negotiates TLS through its OpenSSL
 * backend, verifies the server certificate against the fixture CA (the
 * application supplies the SSL_CTX), and the stub must accept the message.
 *
 * A session whose CA is an unrelated CA must be rejected.
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

#include <libesmtp.h>

static const char MESSAGE[] =
    "From: <sender@localhost>\r\n"
    "To: <rcpt@localhost>\r\n"
    "Subject: phase25-l7-libesmtp\r\n"
    "\r\n"
    "phase25-l7-libesmtp-body\r\n";

static volatile sig_atomic_t g_starttls_ok;
static volatile sig_atomic_t g_invalid_cert;
static volatile sig_atomic_t g_sent;
static int g_status_fd = -1;

static void set_timeout(int fd, int seconds)
{
    struct timeval tv;

    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int send_all(int fd, const char *text, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, text + off, len - off, 0);
        if (n <= 0)
            return 0;
        off += (size_t)n;
    }
    return 1;
}

static int tls_send(SSL *ssl, const char *text)
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

/* Read one CRLF-terminated command line. */
static int read_line(int fd, SSL *ssl, char *buf, size_t cap)
{
    size_t used = 0;

    while (used + 1 < cap) {
        char c;
        int n = ssl != NULL ? SSL_read(ssl, &c, 1) : (int)recv(fd, &c, 1, 0);
        if (n <= 0)
            return 0;
        buf[used++] = c;
        if (used >= 2 && buf[used - 2] == '\r' && buf[used - 1] == '\n') {
            buf[used] = '\0';
            return 1;
        }
    }
    return 0;
}

static void stub(int listen_fd, const char *cert, const char *key)
{
    char line[1024];
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    int in_data = 0;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL || SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
        goto out;
    fd = accept(listen_fd, NULL, NULL);
    if (fd < 0)
        goto out;
    set_timeout(fd, 5);
    if (!send_all(fd, "220 l7 ESMTP\r\n", strlen("220 l7 ESMTP\r\n")))
        goto out;

    while (read_line(fd, NULL, line, sizeof(line))) {
        if (strncmp(line, "EHLO", 4) == 0 || strncmp(line, "HELO", 4) == 0) {
            if (!send_all(fd, "250-l7\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 OK\r\n", strlen("250-l7\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 OK\r\n")))
                goto out;
        } else if (strncmp(line, "STARTTLS", 8) == 0) {
            if (!send_all(fd, "220 go ahead\r\n", strlen("220 go ahead\r\n")))
                goto out;
            ssl = SSL_new(ctx);
            if (ssl == NULL)
                goto out;
            SSL_set_fd(ssl, fd);
            if (SSL_accept(ssl) != 1)
                goto out;
            printf("tls=%s\n",
                   SSL_version(ssl) == TLS1_3_VERSION ? "TLSv1.3" : "other");
            fflush(stdout);
            if (g_status_fd >= 0)
                (void)!write(g_status_fd, "T", 1);
            break;
        } else if (strncmp(line, "QUIT", 4) == 0) {
            send_all(fd, "221 bye\r\n", strlen("221 bye\r\n"));
            goto out;
        } else {
            if (!send_all(fd, "250 OK\r\n", strlen("250 OK\r\n")))
                goto out;
        }
    }

    while (read_line(fd, ssl, line, sizeof(line))) {
        if (in_data) {
            if (strcmp(line, ".\r\n") == 0) {
                if (!tls_send(ssl, "250 message accepted\r\n"))
                    goto out;
                printf("message=accepted\n");
                fflush(stdout);
                if (g_status_fd >= 0)
                    (void)!write(g_status_fd, "A", 1);
                in_data = 0;
            }
            continue;
        }
        if (strncmp(line, "EHLO", 4) == 0 || strncmp(line, "HELO", 4) == 0) {
            if (!tls_send(ssl, "250-l7\r\n250 OK\r\n"))
                goto out;
        } else if (strncmp(line, "MAIL FROM", 9) == 0 ||
                   strncmp(line, "RCPT TO", 7) == 0) {
            if (!tls_send(ssl, "250 OK\r\n"))
                goto out;
        } else if (strncmp(line, "DATA", 4) == 0) {
            if (!tls_send(ssl, "354 end with .\r\n"))
                goto out;
            in_data = 1;
        } else if (strncmp(line, "QUIT", 4) == 0) {
            tls_send(ssl, "221 bye\r\n");
            goto out;
        } else {
            if (!tls_send(ssl, "250 OK\r\n"))
                goto out;
        }
    }
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

static void event_cb(smtp_session_t session, int event_no, void *arg, ...)
{
    (void)session;
    (void)arg;
    if (event_no == SMTP_EV_STARTTLS_OK)
        g_starttls_ok = 1;
    else if (event_no == SMTP_EV_INVALID_PEER_CERTIFICATE)
        g_invalid_cert = 1;
    else if (event_no == SMTP_EV_MESSAGESENT)
        g_sent = 1;
}

static const char *message_cb(void **ctx, int *len, void *arg)
{
    (void)arg;
    if (len == NULL)
        return NULL;    /* release notification */
    if (ctx != NULL && *ctx == NULL) {
        *ctx = (void *)1;
        *len = (int)strlen(MESSAGE);
        return MESSAGE;
    }
    *len = 0;
    return NULL;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL;
    int port, rc = 1, negative = 0;
    pid_t child;
    int lfd, status_pipe[2];
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    int one = 1;
    smtp_session_t session;
    smtp_message_t message;
    SSL_CTX *ssl_ctx;
    char hostport[64];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            printf("libesmtp-l7-harness\n");
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
        fprintf(stderr, "usage: %s --cert F --key F --ca F [--negative]\n", argv[0]);
        return 2;
    }

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0)
        return 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&sin, sizeof(sin)) != 0 ||
        listen(lfd, 4) != 0 ||
        getsockname(lfd, (struct sockaddr *)&sin, &slen) != 0)
        return 1;
    port = ntohs(sin.sin_port);
    if (pipe(status_pipe) != 0)
        return 1;
    child = fork();
    if (child == 0) {
        close(status_pipe[0]);
        g_status_fd = status_pipe[1];
        stub(lfd, cert, key);
        close(lfd);
        _exit(0);
    }
    close(status_pipe[1]);
    close(lfd);

    session = smtp_create_session();
    if (session == NULL)
        goto done;
    snprintf(hostport, sizeof(hostport), "127.0.0.1:%d", port);
    if (!smtp_set_server(session, hostport) || !smtp_set_hostname(session, "localhost"))
        goto done;
    smtp_set_eventcb(session, event_cb, NULL);
    if (!smtp_starttls_enable(session, Starttls_REQUIRED))
        goto done;
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == NULL)
        goto done;
    if (SSL_CTX_load_verify_locations(ssl_ctx, ca, NULL) != 1 ||
        SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
        SSL_CTX_free(ssl_ctx);
        goto done;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    if (!smtp_starttls_set_ctx(session, ssl_ctx)) {
        SSL_CTX_free(ssl_ctx);
        goto done;
    }

    message = smtp_add_message(session);
    if (message == NULL)
        goto done;
    smtp_set_reverse_path(message, "sender@localhost");
    if (smtp_add_recipient(message, "rcpt@localhost") == NULL)
        goto done;
    smtp_set_messagecb(message, message_cb, NULL);

    if (smtp_start_session(session)) {
        (void)rc;
    }
    {
        char seen[8];
        ssize_t n;
        int saw_tls = 0, saw_accepted = 0;

        usleep(200000);
        while ((n = read(status_pipe[0], seen, sizeof(seen))) > 0) {
            for (ssize_t i = 0; i < n; i++) {
                if (seen[i] == 'T')
                    saw_tls = 1;
                else if (seen[i] == 'A')
                    saw_accepted = 1;
            }
        }
        close(status_pipe[0]);
        if (negative) {
            if (!saw_tls) {
                printf("negative=rejected\n");
                rc = 0;
            } else {
                fprintf(stderr, "libesmtp: the unrelated CA completed the TLS handshake\n");
            }
        } else if (saw_tls && saw_accepted && g_starttls_ok && g_sent) {
            printf("starttls=ok\n");
            printf("session=ok\n");
            rc = 0;
        } else {
            fprintf(stderr, "libesmtp: the submission did not complete over STARTTLS\n");
        }
    }
 done:
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    fflush(NULL);
    /* The session is a process-lifetime object here; upstream's teardown after a
     * completed session crashes identically under both subjects, so it is not
     * part of this workload's assertion. */
    _exit(rc);
}
