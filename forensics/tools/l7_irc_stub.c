/*
 * l7_irc_stub.c — a deterministic local IRC peer for the Phase-25 L7 workloads.
 *
 * This is a *peer*, not the program under test: it is compiled against the admitted authority's
 * libssl so an eggdrop/irssi client linked to the subject prefix is driven by an independent
 * OpenSSL implementation over loopback. It performs one job: speak enough IRC to register a client
 * (RPL_WELCOME 001) and to complete a channel join, recording exactly what arrived so the runtime
 * harness can assert that registration happened over TLS -- and that it did not happen when the
 * client's TLS path is refused or the transport is plaintext.
 *
 * Usage:
 *   l7_irc_stub <port> <logfile> <tls|plain> [<cert.pem> <key.pem>]
 *
 * The log is line-oriented and is fsync-free deliberately (the harness reads it while the process
 * lives):
 *   READY <port>
 *   HANDSHAKE ok|fail
 *   C: <line>              every complete IRC line received
 *   REGISTERED <nick>      after the 001 was sent
 *   JOINED <channel>       after the join echo and the fixture PRIVMSG were sent
 *   EOF
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define LINE_MAX_LEN 8192
#define FIXTURE_TEXT "phase24 runtime irc fixture"

static FILE *logf;

static void note(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(logf, fmt, ap);
    va_end(ap);
    fputc('\n', logf);
    fflush(logf);
}

static int send_all(SSL *ssl, int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = ssl ? SSL_write(ssl, buf + off, (int)(len - off))
                    : (int)send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static void handle_line(SSL *ssl, int fd, char *line, char **nick, int *registered) {
    char out[1024];
    note("C: %s", line);

    if (strncasecmp(line, "CAP ", 4) == 0) {
        /* A client that asks for capabilities waits for the reply. Answer LS with an empty set, ACK
         * an explicit request, and ignore END traffic: replying to CAP END would restart the
         * negotiation and the client would loop. */
        const char *sub = line + 4;
        while (*sub == ' ') sub++;
        if (strncasecmp(sub, "LS", 2) == 0) {
            snprintf(out, sizeof(out), ":l7.stub CAP * LS :\r\n");
            (void)send_all(ssl, fd, out, strlen(out));
        } else if (strncasecmp(sub, "REQ ", 4) == 0) {
            snprintf(out, sizeof(out), ":l7.stub CAP * ACK :%s\r\n", sub + 4);
            (void)send_all(ssl, fd, out, strlen(out));
        } else if (strncasecmp(sub, "LIST", 4) == 0) {
            snprintf(out, sizeof(out), ":l7.stub CAP * LIST :\r\n");
            (void)send_all(ssl, fd, out, strlen(out));
        }
        return;
    }

    if (strncasecmp(line, "NICK ", 5) == 0) {
        free(*nick);
        *nick = strdup(line + 5);
        return;
    }
    if (strncasecmp(line, "USER ", 5) == 0) {
        const char *n = *nick ? *nick : "l7client";
        if (!*registered) {
            snprintf(out, sizeof(out),
                     ":l7.stub 001 %s :Welcome to the Phase-25 fixture network\r\n", n);
            if (send_all(ssl, fd, out, strlen(out)) == 0) {
                note("REGISTERED %s", n);
                *registered = 1;
            }
        }
        return;
    }
    if (strncasecmp(line, "JOIN ", 5) == 0) {
        const char *n = *nick ? *nick : "l7client";
        char chan[256];
        const char *p = line + 5;
        while (*p == ' ') p++;
        size_t i = 0;
        while (*p && *p != ',' && *p != ' ' && i + 1 < sizeof(chan)) chan[i++] = *p++;
        chan[i] = '\0';
        if (i == 0) return;
        snprintf(out, sizeof(out), ":%s!%s@l7.stub JOIN :%s\r\n", n, n, chan);
        if (send_all(ssl, fd, out, strlen(out)) != 0) return;
        snprintf(out, sizeof(out), ":%s!%s@l7.stub PRIVMSG %s :%s\r\n", n, n, chan, FIXTURE_TEXT);
        if (send_all(ssl, fd, out, strlen(out)) != 0) return;
        note("JOINED %s", chan);
        return;
    }
    if (strncasecmp(line, "PING", 4) == 0) {
        snprintf(out, sizeof(out), "PONG%s\r\n", line + 4);
        (void)send_all(ssl, fd, out, strlen(out));
    }
}

static void serve(SSL *ssl, int fd) {
    char buf[LINE_MAX_LEN];
    size_t used = 0;
    char *nick = NULL;
    int registered = 0;

    for (;;) {
        int n = ssl ? SSL_read(ssl, buf + used, (int)(sizeof(buf) - used - 1))
                    : (int)recv(fd, buf + used, sizeof(buf) - used - 1, 0);
        if (n <= 0) break;
        used += (size_t)n;
        buf[used] = '\0';
        char *start = buf;
        char *nl;
        while ((nl = strchr(start, '\n')) != NULL) {
            *nl = '\0';
            size_t len = (size_t)(nl - start);
            if (len && start[len - 1] == '\r') start[len - 1] = '\0';
            if (*start) handle_line(ssl, fd, start, &nick, &registered);
            start = nl + 1;
        }
        used = strlen(start);
        memmove(buf, start, used + 1);
        if (used >= sizeof(buf) - 1) used = 0;
    }
    free(nick);
    note("EOF");
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <port> <logfile> <tls|plain> [cert key]\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    int tls = strcmp(argv[3], "tls") == 0;
    logf = fopen(argv[2], "a");
    if (!logf) {
        perror("logfile");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = NULL;
    if (tls) {
        if (argc < 6) {
            fprintf(stderr, "tls mode needs a certificate and key\n");
            return 2;
        }
        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) return 2;
        if (SSL_CTX_use_certificate_file(ctx, argv[4], SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, argv[5], SSL_FILETYPE_PEM) != 1) {
            ERR_print_errors_fp(stderr);
            return 2;
        }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 2;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 2;
    }
    if (listen(lfd, 4) != 0) {
        perror("listen");
        return 2;
    }
    note("READY %d", port);

    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        struct timeval tv = {10, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        SSL *ssl = NULL;
        if (tls) {
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            if (SSL_accept(ssl) != 1) {
                note("HANDSHAKE fail");
                SSL_free(ssl);
                close(fd);
                continue;
            }
            note("HANDSHAKE ok");
        }
        serve(ssl, fd);
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(fd);
    }
    return 0;
}
