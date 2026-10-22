/*
 * dcap-tunnel-ssl L7 workload: the dcap SSL tunnel plugin (libsslTunnel) establishes a TLS
 * tunnel to a loopback peer, sends its auth line and round-trips a payload.
 *
 * `--plain` connects the same plugin to a non-TLS peer; the tunnel establishment must fail, which
 * is the wrong-peer negative control. The plugin's own libssl is the subject library.
 */
#include <openssl/ssl.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "l7_local_tls.h"

extern int eInit(int fd);
extern ssize_t eRead(int fd, void *buff, size_t len);
extern ssize_t eWrite(int fd, const void *buff, size_t len);

static const char *PAYLOAD = "phase25-l7-dcap-tunnel";

static int tunnel_handler(SSL *ssl, void *arg)
{
    char line[256];
    size_t used = 0;
    char payload[64];
    size_t want = strlen(PAYLOAD);
    (void)arg;

    while (used + 1 < sizeof(line)) {
        char c;
        if (!l7_read_full(ssl, &c, 1))
            return -1;
        line[used++] = c;
        if (c == '\n')
            break;
    }
    line[used] = '\0';
    if (strncmp(line, "Auth Protocol V#1.0 auth=", 25) != 0)
        return -1;
    if (!l7_read_full(ssl, payload, want))
        return -1;
    if (memcmp(payload, PAYLOAD, want) != 0)
        return -1;
    return l7_write_all(ssl, payload, want) ? 0 : -1;
}

static void *plain_peer(void *opaque)
{
    int listener = *(int *)opaque;
    int fd = accept(listener, NULL, NULL);
    if (fd >= 0) {
        char buf[512];
        (void)read(fd, buf, sizeof(buf));
        close(fd);
    }
    return NULL;
}

static int plain_listener(int *port_out)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 1) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(addr.sin_port);
    return fd;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL;
    int plain = 0;
    l7_tls_server server;
    int plain_fd = -1;
    int port = 0;
    int fd;
    pthread_t plain_thread;
    struct sockaddr_in addr;
    int pipefd[2];
    ssize_t n;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("dcap-tunnel-ssl-l7-harness\n");
            return 0;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--plain") == 0) {
            plain = 1;
        }
    }

    signal(SIGPIPE, SIG_IGN);

    if (plain) {
        plain_fd = plain_listener(&port);
        if (plain_fd < 0)
            return 2;
        if (pthread_create(&plain_thread, NULL, plain_peer, &plain_fd) != 0)
            return 2;
    } else {
        if (cert == NULL || key == NULL) {
            fprintf(stderr, "usage: %s --cert CRT --key KEY [--plain]\n", argv[0]);
            return 2;
        }
        if (l7_tls_server_start(&server, cert, key, tunnel_handler, NULL, 1) != 0) {
            fprintf(stderr, "the local TLS listener did not start\n");
            return 2;
        }
        port = server.port;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 2;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "connect failed\n");
        return 2;
    }

    if (pipe(pipefd) != 0)
        return 2;
    if (write(pipefd[1], "phase25\nl7pass\n", 16) != 16)
        return 2;
    close(pipefd[1]);
    if (dup2(pipefd[0], STDIN_FILENO) < 0)
        return 2;
    close(pipefd[0]);

    if (eInit(fd) < 0) {
        if (plain) {
            printf("tunnel_peer=rejected\n");
            close(fd);
            close(plain_fd);
            pthread_join(plain_thread, NULL);
            return 0;
        }
        fprintf(stderr, "the TLS tunnel did not establish\n");
        close(fd);
        l7_tls_server_stop(&server);
        return 3;
    }
    if (plain) {
        printf("tunnel_peer=accepted\n");
        close(fd);
        close(plain_fd);
        pthread_join(plain_thread, NULL);
        return 3;
    }

    printf("tunnel=ok\n");
    if (eWrite(fd, PAYLOAD, strlen(PAYLOAD)) != (ssize_t)strlen(PAYLOAD)) {
        printf("payload=write-failed\n");
        close(fd);
        l7_tls_server_stop(&server);
        return 3;
    }
    char reply[64];
    memset(reply, 0, sizeof(reply));
    n = 0;
    while (n < (ssize_t)strlen(PAYLOAD)) {
        ssize_t got = eRead(fd, reply + n, sizeof(reply) - (size_t)n - 1);
        if (got <= 0)
            break;
        n += got;
    }
    if (n != (ssize_t)strlen(PAYLOAD) || memcmp(reply, PAYLOAD, strlen(PAYLOAD)) != 0) {
        printf("payload=mismatch\n");
        close(fd);
        l7_tls_server_stop(&server);
        return 3;
    }
    printf("payload=%s\n", reply);
    close(fd);
    l7_tls_server_stop(&server);
    return 0;
}
