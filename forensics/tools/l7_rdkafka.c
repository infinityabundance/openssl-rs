/* openssl-rs — the librdkafka L7 workload harness.
 *
 * librdkafka is a library-only family: it ships no program of its own. This harness is its admitted
 * consumer. It links the library rebuilt in the pristine tree (and the subject's libssl/libcrypto)
 * and drives the SSL transport directly:
 *
 *   - a local TLS listener (the broker stub) is created in a child process with the fixture cert;
 *   - a producer is configured with `security.protocol=ssl`, the fixture CA and
 *     `api.version.request=false`, so the first thing it sends after the handshake is a Metadata
 *     request;
 *   - the parent requires the stub to report `handshake=ok`, the client's own log to report
 *     `CONNECTED`, the first request bytes to have arrived, and no `SSL handshake failed`;
 *   - `--negative` trusts only the unrelated CA: the handshake must fail certificate verification
 *     on both sides and the client must never report the connection as up.
 *
 * The stub deliberately does not speak the Kafka wire protocol: the assertion is about librdkafka's
 * OpenSSL transport (handshake, certificate verification, connection state), not broker emulation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <rdkafka.h>

#define LOGCAP (64 * 1024)

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_log[LOGCAP];
static size_t g_log_used;
static char g_stats[LOGCAP];
static size_t g_stats_used;
static int g_saw_connected;
static int g_saw_ssl_fail;
static int g_saw_up;

static const char *g_status_path;

static void append_locked(char *buf, size_t *used, const char *text, size_t len) {
    size_t room = LOGCAP - 1 - *used;
    if (len > room) {
        len = room;
    }
    memcpy(buf + *used, text, len);
    *used += len;
    buf[*used] = '\0';
}

static void log_cb(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
    char line[1024];
    int n = snprintf(line, sizeof(line), "%d %s: %s\n", level, fac ? fac : "", buf ? buf : "");
    if (n < 0) {
        return;
    }
    pthread_mutex_lock(&g_lock);
    append_locked(g_log, &g_log_used, line, (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1);
    if (strstr(line, "CONNECTED") != NULL) {
        g_saw_connected = 1;
    }
    if (strstr(line, "SSL handshake failed") != NULL) {
        g_saw_ssl_fail = 1;
    }
    pthread_mutex_unlock(&g_lock);
    (void)rk;
    (void)level;
}

static int stats_cb(rd_kafka_t *rk, char *json, size_t json_len, void *opaque) {
    pthread_mutex_lock(&g_lock);
    g_stats_used = 0;
    append_locked(g_stats, &g_stats_used, json, json_len);
    if (strstr(json, "\"state\":\"UP\"") != NULL) {
        g_saw_up = 1;
    }
    pthread_mutex_unlock(&g_lock);
    (void)rk;
    (void)opaque;
    return 0;
}

static void status(const char *fmt, ...) {
    FILE *f = fopen(g_status_path, "a");
    if (f == NULL) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fflush(f);
    fclose(f);
}

static void set_timeout(int fd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* The broker stub: accept one TLS connection, report the handshake and the first request bytes. */
static void run_stub(int listen_fd, const char *cert, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL || SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        status("handshake=failed\n");
        if (ctx != NULL) {
            SSL_CTX_free(ctx);
        }
        return;
    }
    for (int i = 0; i < 4; i++) {
        fd_set rfds;
        struct timeval tv = {2, 0};
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        int ready = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (ready <= 0) {
            break;
        }
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            break;
        }
        set_timeout(fd, 4);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) == 1) {
            status("handshake=ok\n");
            char buf[4096];
            int total = 0;
            int n;
            while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
                total += n;
                if (total >= 16) {
                    break;
                }
            }
            status("request_bytes=%d\n", total);
            SSL_shutdown(ssl);
        } else {
            status("handshake=failed\n");
        }
        SSL_free(ssl);
        close(fd);
        /* One TLS session is the whole assertion; closing makes the client's state observable. */
        break;
    }
    SSL_CTX_free(ctx);
}

static int set_conf(rd_kafka_conf_t *conf, const char *key, const char *value) {
    char errstr[512];
    if (rd_kafka_conf_set(conf, key, value, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        fprintf(stderr, "config %s=%s failed: %s\n", key, value, errstr);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *cert = NULL, *key = NULL, *ca = NULL;
    int negative = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            printf("librdkafka-l7-harness\n");
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

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listen_fd, 4) != 0) {
        printf("stub=failed\n");
        return 1;
    }
    socklen_t alen = sizeof(addr);
    getsockname(listen_fd, (struct sockaddr *)&addr, &alen);
    int port = ntohs(addr.sin_port);

    char status_path[256];
    snprintf(status_path, sizeof(status_path), "/tmp/l7-rdkafka-status-%d.log", (int)getpid());
    g_status_path = status_path;
    unlink(status_path);

    pid_t child = fork();
    if (child == 0) {
        run_stub(listen_fd, cert, key);
        close(listen_fd);
        _exit(0);
    }
    close(listen_fd);

    char servers[64];
    snprintf(servers, sizeof(servers), "127.0.0.1:%d", port);
    char errstr[512];
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    if (set_conf(conf, "bootstrap.servers", servers) != 0 ||
        set_conf(conf, "security.protocol", "ssl") != 0 ||
        set_conf(conf, "ssl.ca.location", ca) != 0 ||
        set_conf(conf, "ssl.endpoint.identification.algorithm", "none") != 0 ||
        set_conf(conf, "api.version.request", "false") != 0 ||
        set_conf(conf, "debug", "broker,security,protocol") != 0 ||
        set_conf(conf, "statistics.interval.ms", "200") != 0 ||
        set_conf(conf, "socket.timeout.ms", "3000") != 0) {
        rd_kafka_conf_destroy(conf);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    rd_kafka_conf_set_log_cb(conf, log_cb);
    rd_kafka_conf_set_stats_cb(conf, stats_cb);
    rd_kafka_t *rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (rk == NULL) {
        printf("kafka_new=failed: %s\n", errstr);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    for (int i = 0; i < 50; i++) {
        rd_kafka_poll(rk, 100);
        if (g_saw_connected || g_saw_ssl_fail) {
            /* Give the stub time to record the request bytes. */
            rd_kafka_poll(rk, 300);
            break;
        }
    }
    rd_kafka_destroy(rk);
    /* Let the stub finish recording its view of the session before it is stopped. */
    for (int i = 0; i < 60; i++) {
        if (waitpid(child, NULL, WNOHANG) == child) {
            child = -1;
            break;
        }
        usleep(100000);
    }
    if (child > 0) {
        kill(child, SIGTERM);
        waitpid(child, NULL, 0);
    }

    char stub[512] = "";
    FILE *f = fopen(status_path, "r");
    if (f != NULL) {
        size_t n = fread(stub, 1, sizeof(stub) - 1, f);
        stub[n] = '\0';
        fclose(f);
    }
    unlink(status_path);

    int handshake_ok = strstr(stub, "handshake=ok") != NULL;
    int request_ok = strstr(stub, "request_bytes=") != NULL &&
                     strcmp(strstr(stub, "request_bytes=") + strlen("request_bytes="), "0\n") != 0;
    int up = g_saw_up || g_saw_connected;

    if (!negative) {
        printf("handshake=%s\n", handshake_ok ? "ok" : "failed");
        printf("metadata_request=%s\n", request_ok ? "ok" : "failed");
        printf("connected=%s\n", up ? "up" : "down");
        printf("ssl_error=%s\n", g_saw_ssl_fail ? "present" : "none");
        int ok = handshake_ok && request_ok && up && !g_saw_ssl_fail;
        if (!ok) {
            printf("stub=%s\n", stub);
            if (g_saw_ssl_fail) {
                printf("log_ssl_failure=present\n");
            }
        }
        return ok ? 0 : 1;
    }

    printf("handshake=%s\n", g_saw_ssl_fail ? "failed" : "ok");
    printf("metadata_request=%s\n", request_ok ? "ok" : "none");
    printf("connected=%s\n", up ? "up" : "down");
    printf("ssl_error=%s\n", g_saw_ssl_fail ? "certificate verify failed" : "none");
    int rejected = g_saw_ssl_fail && !up && !request_ok;
    printf("negative=%s\n", rejected ? "rejected" : "accepted");
    if (!rejected) {
        printf("stub=%s\n", stub);
    }
    return rejected ? 0 : 1;
}
