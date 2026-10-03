/*
 * rt_statem_probe.c -- RT-STATEM: the Phase-14.5 handshake-state and extension surface, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer, a fixed string or a fixed pointer-identity-free value -- never an
 * address, never a clock, never the error queue, never a socket, never a handshake.
 *
 * ## What this probe drives
 *
 *   * the four handshake-state readers over a fresh connection built from `TLS_method()` and over
 *     NULL: `SSL_get_state` (the authority's `TLS_ST_BEFORE`), `SSL_in_before` (1), `SSL_in_init`
 *     (1) and `SSL_is_init_finished` (0);
 *   * the custom-extension surface: `SSL_extension_supported` over internally supported, unknown
 *     and out-of-16-bit types; `SSL_CTX_add_custom_ext`'s accept/refuse ladder (modern API, the
 *     internally supported type, the SCT exception, a type wider than 16 bits, a `free_cb` with no
 *     `add_cb`, and a duplicate); the two old-style spellings; and `SSL_CTX_has_client_custom_ext`
 *     for a both-roles registration, a client-only registration, a server-only registration and an
 *     unregistered type;
 *   * the signature-algorithm readers over the fresh connection (all the empty answer) and over
 *     NULL, plus `SSL_get1_builtin_sigalgs(NULL)` (the provider-probed list);
 *   * `SSL_check_chain`'s NULL-connection and NULL-chain refusal arms;
 *   * the max-fragment-length setters (0..4 accepted, 5 and 255 refused, NULL connection refused)
 *     and `SSL_SESSION_get_max_fragment_length` over a zeroed session image;
 *   * `SSL_free`/`SSL_CTX_free`, which exercise the custom-extension list's release.
 *
 * ## A note on the session image
 *
 * `SSL_SESSION_get_max_fragment_length` is defined by `t1_lib.c` but dereferences its argument, and
 * the constructor that would build a real one (`SSL_SESSION_new`, `ssl_sess.c`) is 14.7's. The
 * probe therefore passes a zeroed image of the opaque `SSL_SESSION`: the field it reads is zero,
 * which is `TLSEXT_max_fragment_length_*` DISABLED on both sides, and the buffer is far larger than
 * the structure so the read stays inside it. The arm is recorded rather than omitted; it compares
 * the two libraries' answer for the same zeroed image, not a session either side built.
 *
 * ## Arms that are deliberately absent
 *
 * No handshake, no socket and no wall clock move an answer. `SSL_check_chain` is not driven with a
 * real chain: its certificate path is 14.7's and the plan names only the refusal arms here.
 * `SSL_get1_builtin_sigalgs` is driven with a NULL library context (the default one), which is the
 * only context the probe has.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/crypto.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

static int add_cb_ex(SSL *s, unsigned int ext_type, unsigned int context,
                     const unsigned char **out, size_t *outlen, X509 *x,
                     size_t chainidx, int *al, void *add_arg)
{
    (void)s; (void)ext_type; (void)context; (void)out; (void)outlen;
    (void)x; (void)chainidx; (void)al; (void)add_arg;
    return 1;
}

static void free_cb_ex(SSL *s, unsigned int ext_type, unsigned int context,
                       const unsigned char *out, void *add_arg)
{
    (void)s; (void)ext_type; (void)context; (void)out; (void)add_arg;
}

static int parse_cb_ex(SSL *s, unsigned int ext_type, unsigned int context,
                       const unsigned char *in, size_t inlen, X509 *x,
                       size_t chainidx, int *al, void *parse_arg)
{
    (void)s; (void)ext_type; (void)context; (void)in; (void)inlen;
    (void)x; (void)chainidx; (void)al; (void)parse_arg;
    return 1;
}

static int add_cb(SSL *s, unsigned int ext_type, const unsigned char **out,
                  size_t *outlen, int *al, void *add_arg)
{
    (void)s; (void)ext_type; (void)out; (void)outlen; (void)al; (void)add_arg;
    return 1;
}

static void free_cb(SSL *s, unsigned int ext_type, const unsigned char *out,
                    void *add_arg)
{
    (void)s; (void)ext_type; (void)out; (void)add_arg;
}

static int parse_cb(SSL *s, unsigned int ext_type, const unsigned char *in,
                    size_t inlen, int *al, void *parse_arg)
{
    (void)s; (void)ext_type; (void)in; (void)inlen; (void)al; (void)parse_arg;
    return 1;
}

int main(void)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int nid = 12345;
    static unsigned char session_image[65536];

    ctx = SSL_CTX_new(TLS_method());
    out_int("ctx.nonnull", ctx != NULL);
    ssl = SSL_new(ctx);
    out_int("ssl.nonnull", ssl != NULL);

    /* -----------------------------------------------------------------------------------------
     * A. The handshake-state readers.
     * --------------------------------------------------------------------------------------- */
    out_int("state.get_state", SSL_get_state(ssl));
    out_int("state.in_before", SSL_in_before(ssl));
    out_int("state.in_init", SSL_in_init(ssl));
    out_int("state.is_init_finished", SSL_is_init_finished(ssl));
    out_int("state.get_state.null", SSL_get_state(NULL));
    out_int("state.in_before.null", SSL_in_before(NULL));
    out_int("state.in_init.null", SSL_in_init(NULL));
    out_int("state.is_init_finished.null", SSL_is_init_finished(NULL));

    /* -----------------------------------------------------------------------------------------
     * B. The custom-extension surface.
     * --------------------------------------------------------------------------------------- */
    out_int("ext.supported.0", SSL_extension_supported(0));
    out_int("ext.supported.maxfrag", SSL_extension_supported(1));
    out_int("ext.supported.sct", SSL_extension_supported(18));
    out_int("ext.supported.reneg", SSL_extension_supported(0xff01));
    out_int("ext.supported.unknown", SSL_extension_supported(65000));
    out_int("ext.supported.wide", SSL_extension_supported(0x10001));

    out_int("ext.add.custom",
            SSL_CTX_add_custom_ext(ctx, 65000, SSL_EXT_CLIENT_HELLO,
                                   add_cb_ex, free_cb_ex, (void *)1,
                                   parse_cb_ex, (void *)2));
    out_int("ext.has.client.65000", SSL_CTX_has_client_custom_ext(ctx, 65000));
    out_int("ext.add.custom.dup",
            SSL_CTX_add_custom_ext(ctx, 65000, SSL_EXT_CLIENT_HELLO,
                                   add_cb_ex, free_cb_ex, NULL,
                                   parse_cb_ex, NULL));
    out_int("ext.has.client.65001", SSL_CTX_has_client_custom_ext(ctx, 65001));
    out_int("ext.add.internal",
            SSL_CTX_add_custom_ext(ctx, 1, SSL_EXT_CLIENT_HELLO,
                                   add_cb_ex, free_cb_ex, NULL, parse_cb_ex, NULL));
    out_int("ext.add.sct",
            SSL_CTX_add_custom_ext(ctx, 18, SSL_EXT_CLIENT_HELLO,
                                   add_cb_ex, free_cb_ex, NULL, parse_cb_ex, NULL));
    out_int("ext.add.wide",
            SSL_CTX_add_custom_ext(ctx, 70000, SSL_EXT_CLIENT_HELLO,
                                   add_cb_ex, free_cb_ex, NULL, parse_cb_ex, NULL));
    out_int("ext.add.free_no_add",
            SSL_CTX_add_custom_ext(ctx, 65010, SSL_EXT_CLIENT_HELLO,
                                   NULL, free_cb_ex, NULL, NULL, NULL));
    out_int("ext.add.client",
            SSL_CTX_add_client_custom_ext(ctx, 65002, add_cb, free_cb, NULL,
                                          parse_cb, NULL));
    out_int("ext.has.client.65002", SSL_CTX_has_client_custom_ext(ctx, 65002));
    out_int("ext.add.server",
            SSL_CTX_add_server_custom_ext(ctx, 65003, add_cb, free_cb, NULL,
                                          parse_cb, NULL));
    out_int("ext.has.client.65003", SSL_CTX_has_client_custom_ext(ctx, 65003));
    out_int("ext.add.custom.client_dup",
            SSL_CTX_add_custom_ext(ctx, 65002, SSL_EXT_CLIENT_HELLO,
                                   add_cb_ex, free_cb_ex, NULL, parse_cb_ex, NULL));

    /* -----------------------------------------------------------------------------------------
     * C. The signature-algorithm readers.
     * --------------------------------------------------------------------------------------- */
    out_int("sigalg.get_sigalgs.0",
            SSL_get_sigalgs(ssl, 0, &nid, &nid, &nid, NULL, NULL));
    out_int("sigalg.get_sigalgs.neg",
            SSL_get_sigalgs(ssl, -1, &nid, &nid, &nid, NULL, NULL));
    out_int("sigalg.get_shared.0",
            SSL_get_shared_sigalgs(ssl, 0, &nid, &nid, &nid, NULL, NULL));
    out_int("sigalg.get_nid", SSL_get_signature_type_nid(ssl, &nid));
    out_int("sigalg.get_peer_nid", SSL_get_peer_signature_type_nid(ssl, &nid));
    out_int("sigalg.get_sigalgs.null",
            SSL_get_sigalgs(NULL, 0, &nid, &nid, &nid, NULL, NULL));
    out_int("sigalg.get_shared.null",
            SSL_get_shared_sigalgs(NULL, 0, &nid, &nid, &nid, NULL, NULL));
    out_int("sigalg.get_nid.null", SSL_get_signature_type_nid(NULL, &nid));
    out_int("sigalg.get_peer_nid.null", SSL_get_peer_signature_type_nid(NULL, &nid));
    {
        char *builtin = SSL_get1_builtin_sigalgs(NULL);
        out_int("sigalg.builtin.nonnull", builtin != NULL);
        out_str("sigalg.builtin", builtin);
        OPENSSL_free(builtin);
    }

    /* -----------------------------------------------------------------------------------------
     * D. SSL_check_chain's refusal arms.
     * --------------------------------------------------------------------------------------- */
    out_int("check_chain.null_ssl", SSL_check_chain(NULL, NULL, NULL, NULL));
    out_int("check_chain.null_chain", SSL_check_chain(ssl, NULL, NULL, NULL));

    /* -----------------------------------------------------------------------------------------
     * E. The max-fragment-length setters and the session reader.
     * --------------------------------------------------------------------------------------- */
    out_int("mfl.ctx.disabled", SSL_CTX_set_tlsext_max_fragment_length(ctx, 0));
    out_int("mfl.ctx.512", SSL_CTX_set_tlsext_max_fragment_length(ctx, 1));
    out_int("mfl.ctx.4096", SSL_CTX_set_tlsext_max_fragment_length(ctx, 4));
    out_int("mfl.ctx.5.bad", SSL_CTX_set_tlsext_max_fragment_length(ctx, 5));
    out_int("mfl.ctx.255.bad", SSL_CTX_set_tlsext_max_fragment_length(ctx, 255));
    out_int("mfl.ssl.1024", SSL_set_tlsext_max_fragment_length(ssl, 2));
    out_int("mfl.ssl.5.bad", SSL_set_tlsext_max_fragment_length(ssl, 5));
    out_int("mfl.ssl.null", SSL_set_tlsext_max_fragment_length(NULL, 1));
    memset(session_image, 0, sizeof(session_image));
    out_int("mfl.session.zero",
            (long)SSL_SESSION_get_max_fragment_length((SSL_SESSION *)session_image));

    /* -----------------------------------------------------------------------------------------
     * F. Release, exercising the custom-extension list's teardown.
     * --------------------------------------------------------------------------------------- */
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    out_int("freed", 1);
    return 0;
}
