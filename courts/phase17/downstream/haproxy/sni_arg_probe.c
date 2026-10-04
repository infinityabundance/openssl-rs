/*
 * openssl-rs — Phase 17 downstream (HAProxy): isolate the SNI/servername callback ARGUMENT.
 *
 * HAProxy registers (src/ssl_sock.c):
 *     SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);          // arg = NULL
 *     SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk); // -> (ssl, al, priv)
 *     SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);                       // priv = bind_conf
 * and `ssl_sock_switchctx_err_cbk` dereferences `priv` (s->options). HAProxy under the
 * candidate crashes there; this program checks, with no HAProxy involved, which pointer the
 * servername callback actually receives.
 *
 * It forks a same-library server/client pair over a socketpair, drives one handshake, and prints
 * the pointer the callback got versus the pointer that was set. Run it against the candidate and
 * against the authority and compare `arg_matches`.
 *
 * Cert/key paths come from argv[1]/argv[2] (the PEM pair from proxy_probe.sh).
 */
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

static unsigned long MAGIC = 0x5a5a1234UL;
static void *seen_arg = NULL;
static int seen = 0;

static int sni_cb(SSL *ssl, int *al, void *arg)
{
    (void)ssl; (void)al;
    seen = 1;
    seen_arg = arg;
    return SSL_TLSEXT_ERR_OK;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s server.crt server.key\n", argv[0]);
        return 2;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 2; }

    /* A real server writes post-handshake TLS 1.3 tickets; if the client has already closed, that
     * write gets EPIPE. The probe is about the callback argument, not about that race, so SIGPIPE
     * is ignored and the child is allowed to report its verdict. */
    signal(SIGPIPE, SIG_IGN);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }

    if (pid == 0) {
        /* server */
        close(sv[0]);
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) { fprintf(stderr, "server: SSL_CTX_new failed\n"); _exit(3); }
        if (!SSL_CTX_use_certificate_file(ctx, argv[1], SSL_FILETYPE_PEM) ||
            !SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM)) {
            fprintf(stderr, "server: cannot load cert/key\n"); _exit(3);
        }
        SSL_CTX_set_tlsext_servername_callback(ctx, sni_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx, (void *)MAGIC);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sv[1]);
        int r = SSL_accept(ssl);
        if (r != 1)
            dprintf(2, "server: SSL_accept r=%d\n", r);
        /* Report the callback's verdict on stderr (unbuffered) so nothing is lost at _exit. */
        dprintf(2, "server: handshake=%s callback_fired=%d arg_matches=%d\n",
                r == 1 ? "ok" : "fail", seen,
                (seen && seen_arg == (void *)MAGIC) ? 1 : 0);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sv[1]);
        _exit(0);
    }

    /* client */
    close(sv[1]);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    /* A non-IP name so a real SNI extension is sent too. */
    SSL_set_tlsext_host_name(ssl, "localhost");
    SSL_set_fd(ssl, sv[0]);
    int r = SSL_connect(ssl);
    printf("client: handshake=%s\n", r == 1 ? "ok" : "fail");
    fflush(stdout);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sv[0]);

    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st))
        dprintf(2, "parent: server child killed by signal %d\n", WTERMSIG(st));
    else
        dprintf(2, "parent: server child exit=%d\n", WEXITSTATUS(st));
    return 0;
}
