/*
 * Phase-25 L7 workload for the `jimtcl` family.
 *
 * jimtcl's OpenSSL consumer path is the `aio` extension's ssl support
 * (jim-aio.c: SSL_CTX_new/SSL_use_certificate_file/SSL_use_PrivateKey_file/
 * SSL_accept/SSL_read/SSL_write). This runner forks: the child evaluates the
 * Tcl script, which listens on l7_port and runs `$conn ssl -server cert key`,
 * reads one request line and writes one response line; the parent is a plain
 * OpenSSL client that must receive the exact response. The negative control
 * repeats the session with a server key that does not match the certificate,
 * so jim's SSL_accept must fail and the response must not arrive.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <jim.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static const char REQUEST[] = "jimtcl-l7-request\n";
static const char RESPONSE[] = "jimtcl-l7-response";

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

static int connect_retry(int port)
{
    struct sockaddr_in a;
    struct timeval tv = { 20, 0 };
    int tries, fd;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    for (tries = 0; tries < 200; tries++) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            return fd;
        }
        close(fd);
        usleep(50000);
    }
    return -1;
}

static int tls_client(int port, char *out, size_t outlen)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int fd, n;
    char buf[256];

    out[0] = '\0';
    fd = connect_retry(port);
    if (fd < 0)
        return -1;
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        close(fd);
        return -1;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL || SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) != 1) {
        fprintf(stderr, "jimtcl client: handshake failed: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        ERR_clear_error();
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }
    if (SSL_write(ssl, REQUEST, strlen(REQUEST)) <= 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }
    n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0)
        fprintf(stderr, "jimtcl client: read failed: %s (ssl err %d)\n",
                ERR_error_string(ERR_get_error(), NULL), SSL_get_error(ssl, n));
    if (n > 0) {
        buf[n] = '\0';
        snprintf(out, outlen, "%s", buf);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return n > 0 ? 0 : -1;
}

static int run_session(const char *cert, const char *key)
{
    char got[256];
    int port = free_port(), status = 0;
    pid_t pid;

    if (port == 0)
        return 0;
    pid = fork();
    if (pid < 0)
        return 0;
    if (pid == 0) {
        Jim_Interp *interp = Jim_CreateInterp();
        char portstr[32];

        if (interp == NULL)
            _exit(3);
        Jim_RegisterCoreCommands(interp);
        Jim_InitStaticExtensions(interp);
        snprintf(portstr, sizeof(portstr), "%d", port);
        Jim_SetVariableStrWithStr(interp, "l7_cert", cert);
        Jim_SetVariableStrWithStr(interp, "l7_key", key);
        Jim_SetVariableStrWithStr(interp, "l7_port", portstr);
        if (Jim_EvalFile(interp, L7_SCRIPT_PATH) != JIM_OK) {
            fprintf(stderr, "jimtcl server: %s\n", Jim_String(Jim_GetResult(interp)));
            _exit(2);
        }
        _exit(0);
    }
    if (tls_client(port, got, sizeof(got)) != 0)
        got[0] = '\0';
    waitpid(pid, &status, 0);
    return strcmp(got, RESPONSE) == 0;
}

int main(int argc, char **argv)
{
    const char *cert = NULL, *key = NULL, *wrong_key = NULL;
    int i, good, bad;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("jimtcl-l7-harness 1\n");
            return 0;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--wrong-key") == 0 && i + 1 < argc) {
            wrong_key = argv[++i];
        } else {
            fprintf(stderr, "usage: %s --cert FILE --key FILE --wrong-key FILE\n", argv[0]);
            return 3;
        }
    }
    if (cert == NULL || key == NULL || wrong_key == NULL) {
        fprintf(stderr, "harness: --cert, --key and --wrong-key are required\n");
        return 3;
    }

    good = run_session(cert, key);
    printf("tls_session=%s\n", good ? "ok" : "failed");
    printf("payload=%s\n", good ? RESPONSE : "absent");
    bad = run_session(cert, wrong_key);
    printf("wrong_key=%s\n", bad ? "accepted" : "rejected");
    if (good && !bad) {
        printf("result=ok\n");
        return 0;
    }
    printf("result=fail\n");
    return 1;
}
