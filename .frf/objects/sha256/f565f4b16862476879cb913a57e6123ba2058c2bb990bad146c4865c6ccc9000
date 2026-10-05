/*
 * RT-TLS13-INTEROP-MATRIX — one peer of the 2x2 interoperability matrix.
 *
 * Compiled twice, once against the admitted authority's prefix and once against the candidate
 * distribution shell, and exec'd by `rt_tls13_matrix_driver.c` with a connected AF_UNIX socket
 * descriptor. Each process drives exactly one role over a real socket BIO (`BIO_new_socket`) and a
 * blocking TLS 1.3 handshake (SSL_connect / SSL_accept), then exchanges one fixed 15-byte
 * application record with its peer.
 *
 * Two implementations cannot share one process: both the authority and the candidate define the
 * libssl/libcrypto symbols, so the link would collide. The matrix is therefore cross-process, one
 * implementation per process, meeting over the ABI.
 *
 * Every observation is deterministic -- a return code, a boolean, a fixed byte count, a protocol
 * version or an `ERR` rendering -- so nothing reads the clock, a network address or a pointer.
 *
 * argv: <role:client|server> <fd> <cert.pem> <key.pem>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, (long)v);
}

static void out_str(const char *key, const char *v)
{
    if (v == NULL)
        v = "";
    printf("%s=%s\n", key, v);
}

/* The alert either side emits, recorded so a cross-handshake that dies names its stop point. */
static void info_cb(const SSL *s, int where, int ret)
{
    (void)s;
    if ((where & SSL_CB_ALERT) != 0) {
        const char *dir = (where & SSL_CB_READ) != 0 ? "read" : "write";

        printf("alert.%s=%s\n", dir, SSL_alert_desc_string_long(ret));
    }
}

/* The stop point: the `ERR` queue, rendered identically on both implementations. */
static void dump_errors(void)
{
    int i = 0;
    unsigned long e;

    while ((e = ERR_get_error()) != 0 && i < 4) {
        char buf[256];

        ERR_error_string_n(e, buf, sizeof buf);
        printf("err.%d=%s\n", i, buf);
        i++;
    }
    out_int("err.count", i);
}

int main(int argc, char **argv)
{
    const char *role;
    int fd;
    const char *cert, *key;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    unsigned char msg[16] = "ping-over-tls13";
    unsigned char got[32];
    int is_client;
    int ret;

    if (argc < 5) {
        fprintf(stderr, "usage: %s client|server <fd> <cert> <key>\n", argv[0]);
        return 2;
    }
    role = argv[1];
    fd = atoi(argv[2]);
    cert = argv[3];
    key = argv[4];
    is_client = strcmp(role, "client") == 0;

    setvbuf(stdout, NULL, _IOLBF, 0);

    out_str("role", role);

    ctx = SSL_CTX_new(TLS_method());
    out_int("ctx.nonnull", ctx != NULL);
    if (ctx == NULL) {
        dump_errors();
        return 0;
    }
    if (!is_client) {
        out_int("cert.load", SSL_CTX_use_certificate_chain_file(ctx, cert));
        out_int("key.load", SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM));
        out_int("key.check", SSL_CTX_check_private_key(ctx));
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_info_callback(ctx, info_cb);
    /* No session tickets: a post-handshake `NewSessionTicket` would interleave with the fixed
       application record and is not what this cell measures. Both sides accept the option. */
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(ctx, 0);

    ssl = SSL_new(ctx);
    out_int("ssl.nonnull", ssl != NULL);
    if (ssl == NULL) {
        dump_errors();
        SSL_CTX_free(ctx);
        return 0;
    }

    bio = BIO_new_socket(fd, BIO_NOCLOSE);
    out_int("bio.nonnull", bio != NULL);
    if (bio == NULL) {
        dump_errors();
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 0;
    }
    SSL_set_bio(ssl, bio, bio);

    if (is_client)
        ret = SSL_connect(ssl);
    else
        ret = SSL_accept(ssl);
    out_int("handshake.ret", ret);
    if (ret <= 0)
        dump_errors();
    out_int("handshake.finished", SSL_is_init_finished(ssl));
    out_int("handshake.state", SSL_get_state(ssl));
    out_int("handshake.version", SSL_version(ssl));
    out_str("handshake.cipher", SSL_get_cipher_name(ssl));

    if (ret > 0 && SSL_is_init_finished(ssl)) {
        if (is_client) {
            int n;

            out_int("app.write", SSL_write(ssl, msg, (int)strlen((char *)msg)));
            memset(got, 0, sizeof got);
            n = SSL_read(ssl, got, sizeof got);
            out_int("app.read", n);
            if (n < 0)
                dump_errors();
            out_int("app.match", n == (int)strlen((char *)msg)
                    && memcmp(got, msg, (size_t)n) == 0);
        } else {
            int n;

            memset(got, 0, sizeof got);
            n = SSL_read(ssl, got, sizeof got);
            out_int("app.read", n);
            if (n < 0)
                dump_errors();
            out_int("app.match", n == (int)strlen((char *)msg)
                    && memcmp(got, msg, (size_t)n) == 0);
            out_int("app.write", SSL_write(ssl, msg, (int)strlen((char *)msg)));
        }
        out_int("app.exchanged", 1);
    } else {
        out_int("app.exchanged", 0);
    }

    out_int("err.final.count", ERR_peek_error() == 0 ? 0 : 1);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    printf("peer.done=1\n");
    return 0;
}
