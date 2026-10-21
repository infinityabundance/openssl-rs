/* openssl-rs — the dovecot L7 workload client.
 *
 * A small blocking IMAP-over-TLS client linked directly against the subject's libssl. It is the
 * admitted program for the dovecot family (the dovecot executables load their ssl iostream module
 * with dlopen, so their `ldd` never names libssl; this client is the dovecot-owned test consumer
 * that does) and it drives the real installed dovecot IMAPS listener:
 *
 *   greeting -> LOGIN -> APPEND a message -> SELECT INBOX -> FETCH the message back
 *
 * `--negative` trusts only the unrelated CA and must fail certificate verification, so a server
 * that does not present a certificate chaining to the fixture CA is rejected by the client.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define BUFCAP (256 * 1024)

struct opts {
    const char *ca;
    const char *host;
    const char *port;
    const char *user;
    const char *pass;
    const char *message;
    int negative;
};

static int send_all(SSL *ssl, const char *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, data + off, (int)(len - off));
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Read until `needle` appears in the NUL-terminated accumulator, or the socket fails. */
static int read_until(SSL *ssl, char *buf, size_t cap, size_t *used, const char *needle) {
    while (*used + 1 < cap) {
        if (strstr(buf, needle) != NULL) {
            return 0;
        }
        int n = SSL_read(ssl, buf + *used, (int)(cap - 1 - *used));
        if (n <= 0) {
            /* The socket is blocking with SO_RCVTIMEO: WANT_READ here means the peer stopped
             * sending, not that the caller should spin. */
            return -1;
        }
        *used += (size_t)n;
        buf[*used] = '\0';
    }
    return -1;
}

static void step_reset(char *buf, size_t *used) {
    *used = 0;
    buf[0] = '\0';
}

/* Print a short escaped view of the last server response when a step fails. */
static void dump_response(const char *tag, const char *buf) {
    char out[320];
    size_t j = 0;
    for (size_t i = 0; buf[i] != '\0' && i < 300 && j + 3 < sizeof(out); i++) {
        if (buf[i] == '\r') {
            out[j++] = '\\';
            out[j++] = 'r';
        } else if (buf[i] == '\n') {
            out[j++] = '\\';
            out[j++] = 'n';
        } else {
            out[j++] = buf[i];
        }
    }
    out[j] = '\0';
    printf("%s=%s\n", tag, out);
}

static void parse_args(int argc, char **argv, struct opts *o) {
    memset(o, 0, sizeof(*o));
    o->host = "127.0.0.1";
    o->user = "phase25";
    o->pass = "phase25pass";
    o->message = "phase25-dovecot-payload";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            printf("dovecot-l7-harness\n");
            exit(0);
        } else if (!strcmp(argv[i], "--negative")) {
            o->negative = 1;
        } else if (!strcmp(argv[i], "--ca") && i + 1 < argc) {
            o->ca = argv[++i];
        } else if (!strcmp(argv[i], "--host") && i + 1 < argc) {
            o->host = argv[++i];
        } else if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            o->port = argv[++i];
        } else if (!strcmp(argv[i], "--user") && i + 1 < argc) {
            o->user = argv[++i];
        } else if (!strcmp(argv[i], "--pass") && i + 1 < argc) {
            o->pass = argv[++i];
        } else if (!strcmp(argv[i], "--message") && i + 1 < argc) {
            o->message = argv[++i];
        }
    }
    if (o->ca == NULL || o->port == NULL) {
        fprintf(stderr, "usage: %s --ca FILE --port N [--host H] [--negative]\n", argv[0]);
        exit(2);
    }
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    struct timeval tv = {30, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct opts o;
    parse_args(argc, argv, &o);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("client=failed reason=no-tls-context\n");
        return 1;
    }
    if (SSL_CTX_load_verify_locations(ctx, o.ca, NULL) != 1) {
        printf("client=failed reason=ca-load\n");
        SSL_CTX_free(ctx);
        return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    int fd = tcp_connect(o.host, o.port);
    if (fd < 0) {
        printf("client=failed reason=connect\n");
        SSL_CTX_free(ctx);
        return 1;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        long verify = SSL_get_verify_result(ssl);
        unsigned long err = ERR_get_error();
        char errbuf[256] = "none";
        if (err != 0) {
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
        }
        printf("connect=failed\n");
        printf("verify_result=%ld\n", verify);
        printf("error=%s\n", errbuf);
        if (o.negative && verify != X509_V_OK) {
            /* The unrelated CA must be refused: this is the passing negative control. */
            printf("negative=rejected\n");
            SSL_free(ssl);
            close(fd);
            SSL_CTX_free(ctx);
            return 0;
        }
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("handshake=%s\n", SSL_get_version(ssl));
    if (o.negative) {
        /* A handshake that verifies under the unrelated CA is a failed negative control. */
        printf("negative=accepted\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("peer_verify=ok\n");

    char *buf = malloc(BUFCAP);
    if (buf == NULL) {
        printf("client=failed reason=no-buffer\n");
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    size_t used = 0;
    char cmd[512];
    int ok = 1;

    /* The IMAPS greeting. */
    if (read_until(ssl, buf, BUFCAP, &used, "\r\n") != 0 || strncmp(buf, "* OK", 4) != 0) {
        printf("greeting=failed\n");
        ok = 0;
    } else {
        printf("greeting=ok\n");
    }

    if (ok) {
        step_reset(buf, &used);
        snprintf(cmd, sizeof(cmd), "a1 LOGIN %s %s\r\n", o.user, o.pass);
        if (send_all(ssl, cmd, strlen(cmd)) != 0 ||
            read_until(ssl, buf, BUFCAP, &used, "a1 OK") != 0) {
            printf("login=failed\n");
            ok = 0;
        } else {
            printf("login=ok\n");
        }
    }

    if (ok) {
        step_reset(buf, &used);
        char message[1024];
        snprintf(message, sizeof(message), "Subject: phase25\r\n\r\n%s\r\n", o.message);
        size_t mlen = strlen(message);
        snprintf(cmd, sizeof(cmd), "a2 APPEND INBOX (\\Seen) {%zu}\r\n", mlen);
        if (send_all(ssl, cmd, strlen(cmd)) != 0 ||
            read_until(ssl, buf, BUFCAP, &used, "\r\n") != 0 || buf[0] != '+') {
            printf("append=failed\n");
            dump_response("append_response", buf);
            ok = 0;
        } else if (send_all(ssl, message, mlen) != 0) {
            printf("append=failed\n");
            ok = 0;
        } else {
            /* The literal is an argument: the command line's own CRLF follows the literal data. */
            send_all(ssl, "\r\n", 2);
            step_reset(buf, &used);
            if (read_until(ssl, buf, BUFCAP, &used, "a2 OK") != 0) {
                printf("append=failed\n");
                dump_response("append_response", buf);
                ok = 0;
            } else {
                printf("append=ok\n");
            }
        }
    }

    if (ok) {
        step_reset(buf, &used);
        if (send_all(ssl, "a3 SELECT INBOX\r\n", 17) != 0 ||
            read_until(ssl, buf, BUFCAP, &used, "a3 OK") != 0 ||
            strstr(buf, "EXISTS") == NULL) {
            printf("select=failed\n");
            ok = 0;
        } else {
            printf("select=ok\n");
        }
    }

    if (ok) {
        step_reset(buf, &used);
        if (send_all(ssl, "a4 FETCH 1 BODY[]\r\n", 20) != 0 ||
            read_until(ssl, buf, BUFCAP, &used, "a4 OK") != 0 ||
            strstr(buf, o.message) == NULL) {
            printf("payload=failed\n");
            ok = 0;
        } else {
            printf("payload=ok\n");
        }
    }

    step_reset(buf, &used);
    send_all(ssl, "a5 LOGOUT\r\n", 11);
    read_until(ssl, buf, BUFCAP, &used, "a5 OK");

    free(buf);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return ok ? 0 : 1;
}
