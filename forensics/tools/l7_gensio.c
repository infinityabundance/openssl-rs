/*
 * Phase-25 L7 workload for the `gensio` family.
 *
 * gensio ships the `gensiot` tool, but its OpenSSL consumer path is the `ssl`
 * gensio (lib/gensio_ssl.c: SSL_CTX_new/SSL_CTX_use_certificate_file/
 * SSL_CTX_load_verify_locations/SSL_accept/SSL_connect). This harness drives
 * that path directly: an ssl accepter over loopback TCP carries a request and a
 * response between two gensio stacks. The negative control is a second session
 * whose server certificate is signed by an unrelated CA; the client is given
 * only the fixture CA, so the ssl gensio must refuse to open.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char REQUEST[] = "gensio-l7-request";
static const char RESPONSE[] = "gensio-l7-response";

struct session {
    const char *cert;
    const char *key;
    const char *ca;
    int port;
    int negative;
    volatile int started;
    int client_ok;
    int server_ok;
    char err[256];
};

static void do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
                    const char *log, va_list args)
{
    (void)f;
    fprintf(stderr, "gensio %s: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
}

static int free_port(void)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int fd = socket(AF_INET, SOCK_STREAM, 0), port;

    if (fd < 0)
        return 0;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return 0;
    }
    port = ntohs(a.sin_port);
    close(fd);
    return port;
}

static void *server_thread(void *arg)
{
    struct session *s = arg;
    struct gensio_os_funcs *o = NULL;
    struct gensio_os_proc_data *proc = NULL;
    struct gensio_accepter *acc = NULL;
    struct gensio *io = NULL;
    char spec[512], buf[128];
    gensiods count = 0;
    gensio_time timeout = { 20, 0 };
    int rv;

    rv = gensio_alloc_os_funcs(0, &o, 0);
    if (rv)
        goto out;
    gensio_os_funcs_set_vlog(o, do_vlog);
    snprintf(spec, sizeof(spec), "ssl(cert=%s,key=%s),tcp,127.0.0.1,%d",
             s->cert, s->key, s->port);
    rv = str_to_gensio_accepter(spec, o, NULL, NULL, &acc);
    if (rv)
        goto out;
    rv = gensio_acc_set_sync(acc);
    if (rv)
        goto out;
    rv = gensio_acc_startup(acc);
    if (rv)
        goto out;
    s->started = 1;
    rv = gensio_acc_accept_s(acc, &timeout, &io);
    if (rv)
        goto out;
    rv = gensio_set_sync(io);
    if (rv)
        goto out;
    rv = gensio_read_s(io, &count, buf, sizeof(buf) - 1, &timeout);
    if (rv)
        goto out;
    buf[count] = '\0';
    /* A TLS handshake that never completes still yields an io; the request is
     * what proves the session carried application data. */
    s->server_ok = (strcmp(buf, REQUEST) == 0);
    rv = gensio_write_s(io, NULL, RESPONSE, strlen(RESPONSE), &timeout);
    if (rv)
        s->server_ok = 0;
    if (io != NULL) {
        gensio_close_s(io);
        gensio_free(io);
        io = NULL;
    }
    s->err[0] = '\0';
out:
    if (rv)
        snprintf(s->err, sizeof(s->err), "server: %s", gensio_err_to_str(rv));
    if (io != NULL) {
        gensio_close_s(io);
        gensio_free(io);
    }
    if (acc != NULL) {
        gensio_acc_shutdown_s(acc);
        gensio_acc_free(acc);
    }
    if (proc != NULL)
        gensio_os_proc_cleanup(proc);
    if (o != NULL)
        gensio_os_funcs_free(o);
    return NULL;
}

static int run_session(const char *cert, const char *key, const char *ca, int negative,
                       int *server_ok, char *err, size_t errlen)
{
    struct gensio_os_funcs *o = NULL;
    struct gensio_os_proc_data *proc = NULL;
    struct gensio *io = NULL;
    struct session s;
    pthread_t tid;
    char spec[512], buf[128];
    gensiods count = 0;
    gensio_time timeout = { 20, 0 };
    int rv, open_rv, port = free_port(), tries;

    if (port == 0) {
        snprintf(err, errlen, "no free loopback port");
        return -1;
    }
    memset(&s, 0, sizeof(s));
    s.cert = cert;
    s.key = key;
    s.ca = ca;
    s.port = port;
    s.negative = negative;
    if (pthread_create(&tid, NULL, server_thread, &s) != 0) {
        snprintf(err, errlen, "pthread_create failed");
        return -1;
    }
    for (tries = 0; !s.started && tries < 400; tries++)
        usleep(5000);
    if (!s.started) {
        snprintf(err, errlen, "server did not start: %s", s.err);
        pthread_join(tid, NULL);
        return -1;
    }
    rv = gensio_alloc_os_funcs(0, &o, 0);
    if (rv) {
        snprintf(err, errlen, "client os funcs: %s", gensio_err_to_str(rv));
        goto out;
    }
    gensio_os_funcs_set_vlog(o, do_vlog);
    snprintf(spec, sizeof(spec), "ssl(CA=%s),tcp,127.0.0.1,%d", ca, port);
    rv = str_to_gensio(spec, o, NULL, NULL, &io);
    if (rv) {
        snprintf(err, errlen, "client alloc: %s", gensio_err_to_str(rv));
        goto out;
    }
    rv = gensio_set_sync(io);
    if (rv) {
        snprintf(err, errlen, "client set_sync: %s", gensio_err_to_str(rv));
        goto out;
    }
    open_rv = gensio_open_s(io);
    if (open_rv) {
        rv = open_rv;
        snprintf(err, errlen, "client open: %s", gensio_err_to_str(open_rv));
        goto out;
    }
    rv = gensio_write_s(io, NULL, REQUEST, strlen(REQUEST), &timeout);
    if (rv) {
        snprintf(err, errlen, "client write: %s", gensio_err_to_str(rv));
        goto out;
    }
    rv = gensio_read_s(io, &count, buf, sizeof(buf) - 1, &timeout);
    if (rv) {
        snprintf(err, errlen, "client read: %s", gensio_err_to_str(rv));
        goto out;
    }
    buf[count] = '\0';
    rv = (strcmp(buf, RESPONSE) == 0) ? 0 : -1;
    if (rv)
        snprintf(err, errlen, "client payload=%s", buf);
out:
    if (io != NULL) {
        gensio_close_s(io);
        gensio_free(io);
    }
    if (proc != NULL)
        gensio_os_proc_cleanup(proc);
    if (o != NULL)
        gensio_os_funcs_free(o);
    pthread_join(tid, NULL);
    *server_ok = s.server_ok;
    if (s.err[0] != '\0' && *err == '\0')
        snprintf(err, errlen, "%s", s.err);
    return rv;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *ca = NULL, *other_ca = NULL;
    char err[256];
    struct gensio_os_funcs *o = NULL;
    struct gensio_os_proc_data *proc = NULL;
    int i, server_ok = 0, good, bad, rv;

    rv = gensio_alloc_os_funcs(0, &o, 0);
    if (rv)
        return 1;
    rv = gensio_os_proc_setup(o, &proc);
    if (rv)
        return 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("gensio-l7-harness 1\n");
            return 0;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca = argv[++i];
        } else if (strcmp(argv[i], "--other-ca") == 0 && i + 1 < argc) {
            other_ca = argv[++i];
        } else {
            fprintf(stderr, "usage: %s --cert FILE --key FILE --ca FILE --other-ca FILE\n",
                    argv[0]);
            return 3;
        }
    }
    if (!cert || !key || !ca || !other_ca) {
        fprintf(stderr, "harness: --cert, --key, --ca and --other-ca are required\n");
        return 3;
    }

    err[0] = '\0';
    good = run_session(cert, key, ca, 0, &server_ok, err, sizeof(err));
    good = (good == 0 && server_ok) ? 0 : 1;
    printf("tls_session=%s\n", good == 0 ? "ok" : "failed");
    printf("payload_round_trip=%s\n", good == 0 ? "ok" : "failed");

    err[0] = '\0';
    bad = run_session(cert, key, other_ca, 1, &server_ok, err, sizeof(err));
    printf("wrong_ca=%s\n", bad != 0 ? "rejected" : "accepted");

    if (good == 0 && bad != 0) {
        printf("result=ok\n");
        gensio_os_proc_cleanup(proc);
        gensio_os_funcs_free(o);
        return 0;
    }
    printf("result=fail\n");
    gensio_os_proc_cleanup(proc);
    gensio_os_funcs_free(o);
    return 1;
}
