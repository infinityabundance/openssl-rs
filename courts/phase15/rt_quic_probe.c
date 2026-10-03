/*
 * rt_quic_probe.c -- RT-QUIC: the Phase-15.1 QUIC method constructors, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed string -- never an address, never a clock, never the
 * error queue -- and no handshake, socket or timer moves an answer.
 *
 * ## What this probe drives
 *
 * The whole of `src/ssl/quic/quic_method.rs`, `ssl/quic/quic_method.c`'s three constructors and
 * the surface each installs:
 *
 *   * every constructor is non-NULL, and the three are distinct process-lifetime statics
 *     (`SSL_CTX_get_ssl_method` reports each back by identity);
 *   * `SSL_CTX_new` accepts each one and the context reports the method it was built from;
 *   * the context's default timeout (`SSL_CTX_get_timeout`), which is the method's own
 *     `tls1_default_timeout`;
 *   * the version-inflexible bound arm: `SSL_CONF_cmd(ctx, "MinProtocol", "TLSv1.2")` runs
 *     `ssl_set_version_bound` with the method's own `version` (`OSSL_QUIC_ANY_VERSION`, which is
 *     neither `TLS_ANY_VERSION` nor `DTLS_ANY_VERSION`), so the bound is ignored and the context
 *     keeps reporting a zero minimum. The observation is the pair (the command's return, the
 *     context's minimum afterwards), and it is what makes the method's version field visible
 *     without building a connection;
 *   * the refusal arm `SSL_CTX_new(NULL)`.
 *
 * ## Arms that are deliberately absent
 *
 * `SSL_new` is **not** driven. The authority's `ossl_quic_new` (`quic_impl.c:591`) builds a
 * `QUIC_CONNECTION` -- and refuses `OSSL_QUIC_server_method` outright with
 * `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED` -- while this crate builds no QUIC object, so a candidate
 * connection from these methods is an ordinary `SSL` object and would report `SSL_is_quic == 0`
 * and `SSL_version == 0xFFFFF` where the authority reports `1` and `OSSL_QUIC1_VERSION`. That is
 * the QUIC implementation object, which is not this unit's; the divergence is recorded in
 * `src/ssl/quic/quic_method.rs` rather than diffed as a residual. `SSL_CTX_set_ssl_version`'s
 * `IS_QUIC_CTX` refusal is absent for the same reason (the contexts this crate builds never reach
 * the arm; `src/ssl/ssl_lib.rs:8701`).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/quic.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

typedef const SSL_METHOD *(*meth_fn)(void);

/* Drive one constructor, its context and the method surface it installs. */
static void probe_meth(const char *name, meth_fn fn)
{
    char key[128];
    const SSL_METHOD *m = fn();
    SSL_CONF_CTX *cctx;
    SSL_CTX *ctx;

#define K(fmt) (snprintf(key, sizeof(key), "%s.%s", name, fmt), key)

    out_int(K("nonnull"), m != NULL);
    ctx = SSL_CTX_new(m);
    out_int(K("ctx.nonnull"), ctx != NULL);
    out_int(K("ctx.method_identity"), SSL_CTX_get_ssl_method(ctx) == m);
    out_int(K("ctx.timeout"), SSL_CTX_get_timeout(ctx));
    out_int(K("ctx.min_proto"), SSL_CTX_get_min_proto_version(ctx));
    out_int(K("ctx.max_proto"), SSL_CTX_get_max_proto_version(ctx));

    /* The method's own `version` decides whether a protocol bound is stored: a QUIC method is
     * neither `TLS_ANY_VERSION` nor `DTLS_ANY_VERSION`, so `ssl_set_version_bound` ignores it. */
    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    out_int(K("conf.min_proto.ret"), SSL_CONF_cmd(cctx, "MinProtocol", "TLSv1.2"));
    out_int(K("conf.min_proto.after"), SSL_CTX_get_min_proto_version(ctx));
    SSL_CONF_CTX_free(cctx);

    SSL_CTX_free(ctx);

#undef K
}

int main(void)
{
    const SSL_METHOD *client = OSSL_QUIC_client_method();
    const SSL_METHOD *thread = OSSL_QUIC_client_thread_method();
    const SSL_METHOD *server = OSSL_QUIC_server_method();

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ----------------------------------------------------------------------------------------
     * A. The three statics, and the context/method surface each installs.
     * -------------------------------------------------------------------------------------- */
    probe_meth("client", OSSL_QUIC_client_method);
    probe_meth("client_thread", OSSL_QUIC_client_thread_method);
    probe_meth("server", OSSL_QUIC_server_method);

    /* ----------------------------------------------------------------------------------------
     * B. Identity: each constructor returns its own static, and the three are distinct.
     * -------------------------------------------------------------------------------------- */
    out_int("distinct.client_ne_thread", client != thread);
    out_int("distinct.client_ne_server", client != server);
    out_int("distinct.thread_ne_server", thread != server);
    out_int("distinct.client_stable", OSSL_QUIC_client_method() == client);
    out_int("distinct.server_stable", OSSL_QUIC_server_method() == server);

    /* ----------------------------------------------------------------------------------------
     * C. The refusal arm.
     * -------------------------------------------------------------------------------------- */
    out_int("null.ctx_new_refused", SSL_CTX_new(NULL) == NULL);

    return 0;
}
