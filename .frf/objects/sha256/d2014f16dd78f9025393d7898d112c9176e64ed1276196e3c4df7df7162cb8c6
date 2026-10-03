/*
 * rt_ssl_bio_probe.c -- RT-SSL-BIO: the Phase-14.6 BIO pair, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed string -- never an address, never a clock, never the
 * error queue, never a socket, never a handshake.
 *
 * ## What this probe drives
 *
 *   * the `BIO_f_ssl` method: a BIO built from it answers `BIO_TYPE_SSL` and the name `"ssl"`, and
 *     starts with `init = 0` / `shutdown = BIO_CLOSE`;
 *   * `BIO_new_ssl(ctx, client)` over a fixed `TLS_method()` context: the handle is non-NULL, its
 *     embedded `SSL` is non-NULL, `SSL_is_server` follows `client`, `init` is 1 and `shutdown` is
 *     `BIO_CLOSE`; `BIO_new_ssl(NULL, 1)` is the NULL-refusal arm;
 *   * the `BIO_C_SSL_MODE` control, which flips the embedded connection's role;
 *   * the renegotiation controls `BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT`/`_BYTES` (their
 *     previous-value returns and the `< 60`/`< 512` clamps) and `BIO_C_GET_SSL_NUM_RENEGOTIATES`;
 *   * `BIO_new_ssl_connect` and `BIO_new_buffer_ssl_connect` over the fixed context: non-NULL, the
 *     filter method each head carries, and the NULL-context refusal;
 *   * `BIO_ssl_copy_session_id`'s refusal arms (NULL, non-SSL BIOs, a pair whose `SSL` is NULL) and
 *     its accepted arm over two distinct fresh SSL BIOs;
 *   * `BIO_ssl_shutdown` over NULL and over a three-BIO chain, with the embedded connection's
 *     `SSL_get_shutdown` read back on both sides of the call.
 *
 * ## Arms that are deliberately absent
 *
 * No data is read or written through the pair, so the renegotiation trigger (which needs
 * `SSL_renegotiate` and a handshake) never fires and `BIO_read`/`BIO_write` on the SSL BIO are not
 * driven. `BIO_CTRL_PENDING`/`_FLUSH`/`BIO_C_GET_FD` are not driven because a fresh SSL BIO has no
 * `rbio`/`wbio` and both libraries dereference it there. No socket and no handshake move an answer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

int main(void)
{
    SSL_CTX *ctx;
    BIO *b, *sb, *sb2, *sc, *bc, *t, *f, *mem1, *mem2, *fresh;
    SSL *ssl = NULL, *ssl2 = NULL, *tssl = NULL;

    ctx = SSL_CTX_new(TLS_method());
    out_int("ctx.nonnull", ctx != NULL);

    /* -----------------------------------------------------------------------------------------
     * A. The BIO_f_ssl method and a raw BIO from it.
     * --------------------------------------------------------------------------------------- */
    out_int("f_ssl.nonnull", BIO_f_ssl() != NULL);
    b = BIO_new(BIO_f_ssl());
    out_int("f_ssl.bio.nonnull", b != NULL);
    out_int("f_ssl.method_type", BIO_method_type(b));
    out_str("f_ssl.method_name", BIO_method_name(b));
    out_int("f_ssl.init", BIO_get_init(b));
    out_int("f_ssl.shutdown", BIO_get_shutdown(b));
    out_int("f_ssl.data.nonnull", BIO_get_data(b) != NULL);
    out_int("f_ssl.get_ssl", BIO_get_ssl(b, &ssl));
    out_int("f_ssl.get_ssl.null", ssl == NULL);

    /* -----------------------------------------------------------------------------------------
     * B. BIO_new_ssl over the fixed context, and its refusal arm.
     * --------------------------------------------------------------------------------------- */
    sb = BIO_new_ssl(ctx, 1);
    out_int("new_ssl.client.nonnull", sb != NULL);
    out_int("new_ssl.client.get", BIO_get_ssl(sb, &ssl));
    out_int("new_ssl.client.ssl.nonnull", ssl != NULL);
    out_int("new_ssl.client.is_server", SSL_is_server(ssl));
    out_int("new_ssl.client.init", BIO_get_init(sb));
    out_int("new_ssl.client.shutdown", BIO_get_shutdown(sb));
    out_int("new_ssl.client.method_type", BIO_method_type(sb));

    sb2 = BIO_new_ssl(ctx, 0);
    out_int("new_ssl.server.nonnull", sb2 != NULL);
    out_int("new_ssl.server.get", BIO_get_ssl(sb2, &ssl2));
    out_int("new_ssl.server.is_server", SSL_is_server(ssl2));

    out_int("new_ssl.null_ctx", BIO_new_ssl(NULL, 1) != NULL);

    /* -----------------------------------------------------------------------------------------
     * C. The BIO_C_SSL_MODE control.
     * --------------------------------------------------------------------------------------- */
    out_int("mode.server_to_accept", BIO_ctrl(sb2, BIO_C_SSL_MODE, 0, NULL) >= 0);
    out_int("mode.server.is_server", SSL_is_server(ssl2));
    out_int("mode.server_to_connect", BIO_ctrl(sb2, BIO_C_SSL_MODE, 1, NULL) >= 0);
    out_int("mode.client.is_server", SSL_is_server(ssl2));

    /* -----------------------------------------------------------------------------------------
     * D. The renegotiation controls.
     * --------------------------------------------------------------------------------------- */
    out_int("reneg.timeout.first", BIO_ctrl(sb, BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT, 100, NULL));
    out_int("reneg.timeout.second", BIO_ctrl(sb, BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT, 30, NULL));
    out_int("reneg.bytes.first", BIO_ctrl(sb, BIO_C_SET_SSL_RENEGOTIATE_BYTES, 1024, NULL));
    out_int("reneg.bytes.small", BIO_ctrl(sb, BIO_C_SET_SSL_RENEGOTIATE_BYTES, 100, NULL));
    out_int("reneg.bytes.second", BIO_ctrl(sb, BIO_C_SET_SSL_RENEGOTIATE_BYTES, 2048, NULL));
    out_int("reneg.count", BIO_ctrl(sb, BIO_C_GET_SSL_NUM_RENEGOTIATES, 0, NULL));

    /* -----------------------------------------------------------------------------------------
     * E. BIO_new_ssl_connect and BIO_new_buffer_ssl_connect.
     * --------------------------------------------------------------------------------------- */
    sc = BIO_new_ssl_connect(ctx);
    out_int("new_ssl_connect.nonnull", sc != NULL);
    out_int("new_ssl_connect.method_type", BIO_method_type(sc));
    out_int("new_ssl_connect.next.nonnull", BIO_next(sc) != NULL);
    out_int("new_ssl_connect.null_ctx", BIO_new_ssl_connect(NULL) != NULL);

    bc = BIO_new_buffer_ssl_connect(ctx);
    out_int("new_buffer_ssl_connect.nonnull", bc != NULL);
    out_int("new_buffer_ssl_connect.method_type", BIO_method_type(bc));
    out_int("new_buffer_ssl_connect.next.nonnull", BIO_next(bc) != NULL);
    out_int("new_buffer_ssl_connect.null_ctx", BIO_new_buffer_ssl_connect(NULL) != NULL);

    /* -----------------------------------------------------------------------------------------
     * F. BIO_ssl_copy_session_id: the refusal arms and the accepted arm.
     * --------------------------------------------------------------------------------------- */
    out_int("copy.null_null", BIO_ssl_copy_session_id(NULL, NULL));
    mem1 = BIO_new(BIO_s_mem());
    mem2 = BIO_new(BIO_s_mem());
    out_int("copy.mem_mem", BIO_ssl_copy_session_id(mem1, mem2));
    fresh = BIO_new(BIO_f_ssl());
    out_int("copy.fresh_ssl", BIO_ssl_copy_session_id(fresh, sb));
    t = BIO_new_ssl(ctx, 1);
    f = BIO_new_ssl(ctx, 1);
    out_int("copy.ssl.ssl", BIO_ssl_copy_session_id(t, f));
    out_int("copy.t.get", BIO_get_ssl(t, &tssl));
    out_int("copy.t.cert", SSL_get_certificate(tssl) == NULL);

    /* -----------------------------------------------------------------------------------------
     * G. BIO_ssl_shutdown over NULL and over a chain.
     * --------------------------------------------------------------------------------------- */
    BIO_ssl_shutdown(NULL);
    out_int("shutdown.null.survived", 1);
    out_int("shutdown.before", SSL_get_shutdown(ssl));
    BIO_ssl_shutdown(sb);
    out_int("shutdown.after", SSL_get_shutdown(ssl));
    BIO_ssl_shutdown(bc);
    out_int("shutdown.chain.survived", 1);

    /* -----------------------------------------------------------------------------------------
     * H. Release.
     * --------------------------------------------------------------------------------------- */
    BIO_free(mem1);
    BIO_free(mem2);
    BIO_free(fresh);
    BIO_free_all(b);
    BIO_free_all(sb);
    BIO_free_all(sb2);
    BIO_free_all(sc);
    BIO_free_all(bc);
    BIO_free_all(t);
    BIO_free_all(f);
    SSL_CTX_free(ctx);
    out_int("freed", 1);
    return 0;
}
