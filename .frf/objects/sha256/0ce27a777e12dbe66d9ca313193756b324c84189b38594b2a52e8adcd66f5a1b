/*
 * rt_ssl_methods_probe.c -- RT-SSL-METHODS: the Phase-14.2 method and version tables, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed string -- never an address, never a clock, never the
 * error queue -- and no handshake, socket or timer moves an answer.
 *
 * ## What this probe drives
 *
 * The 21 `TLS_*`/`DTLS_*`/`TLSv1_*` constructors `src/ssl/methods.rs` lands, and the version
 * surface it installs:
 *
 *   * every constructor is non-NULL, and `SSL_CTX_new` accepts each one;
 *   * the context reports the method it was built from (`SSL_CTX_get_ssl_method` identity), and
 *     `SSL_new` allocates a connection from it;
 *   * the connection's version (`SSL_version`, `SSL_client_version`, `SSL_get_version`), the
 *     datagram flag (`SSL_is_dtls`), the role (`SSL_is_server`) and the default timeout
 *     (`SSL_get_default_timeout`), which is the method's own `tls1_default_timeout` /
 *     `dtls1_default_timeout`;
 *   * the version bounds a fresh context reports (`SSL_CTX_get_min_proto_version` /
 *     `_max_`, and their connection twins);
 *   * `SSL_group_to_name` and `SSL_get0_group_name`: the unknown/refused arms only (see below),
 *     plus the NULL connection arm of `SSL_get0_group_name`;
 *   * `SSL_CTX_set_tlsext_ticket_key_evp_cb`, whose return is the whole observable (the authority
 *     exposes no getter for the stored callback, so the arm is the setter and its NULL re-set);
 *   * the refusal arms `SSL_CTX_new(NULL)` and `SSL_new(NULL)`, and the NULL-context
 *     `SSL_CTX_get_min_proto_version(NULL)` / `_max_` (which reach `SSL_CTX_ctrl(NULL, ...)`).
 *
 * ## Arms that are deliberately absent
 *
 * `SSL_get0_group_name` is not driven on a live connection: for a non-TLS1.3 method the authority
 * reads `sc->session->kex_group` (`s3_lib.c:5654`) and `sc->session` is NULL until a handshake
 * allocates one, so the authority faults. Only its NULL-connection arm is compared.
 * `SSL_group_to_name`'s known-NID arm (`NID_X9_62_prime256v1` -> `secp256r1`) is `pending`, not
 * compared: the authority's answer comes from the context group table `ssl_load_groups` (14.5)
 * builds, which the candidate does not yet build, so the candidate answers NULL. The unknown-NID
 * and unknown-raw-group-id arms below are the ones both sides agree on. `SSL_version(NULL)` and
 * `SSL_get_version(NULL)` are not driven either: the authority dereferences `s->type` before its
 * NULL check, so a probe would crash both the authority and the candidate rather than compare them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

/* The one callback `SSL_CTX_set_tlsext_ticket_key_evp_cb` installs; its body never runs. */
static int ticket_key_evp_cb(SSL *s, unsigned char *name, unsigned char *iv,
                             EVP_CIPHER_CTX *cctx, EVP_MAC_CTX *mctx, int enc)
{
    (void)s;
    (void)name;
    (void)iv;
    (void)cctx;
    (void)mctx;
    return enc;
}

typedef const SSL_METHOD *(*meth_fn)(void);

/* Drive one constructor, its context/connection and every version accessor it installs. */
static void probe_meth(const char *name, meth_fn fn)
{
    char key[128];
    const SSL_METHOD *m = fn();
    SSL_CTX *ctx;
    SSL *ssl;

#define K(fmt) (snprintf(key, sizeof(key), "%s.%s", name, fmt), key)

    out_int(K("nonnull"), m != NULL);
    ctx = SSL_CTX_new(m);
    out_int(K("ctx.nonnull"), ctx != NULL);
    out_int(K("ctx.method_identity"), SSL_CTX_get_ssl_method(ctx) == m);
    ssl = SSL_new(ctx);
    out_int(K("ssl.nonnull"), ssl != NULL);
    out_int(K("ssl.version"), SSL_version(ssl));
    out_int(K("ssl.client_version"), SSL_client_version(ssl));
    out_str(K("ssl.version_str"), SSL_get_version(ssl));
    out_int(K("ssl.is_dtls"), SSL_is_dtls(ssl));
    out_int(K("ssl.is_server"), SSL_is_server(ssl));
    out_int(K("ssl.default_timeout"), SSL_get_default_timeout(ssl));
    out_int(K("ctx.min_proto"), SSL_CTX_get_min_proto_version(ctx));
    out_int(K("ctx.max_proto"), SSL_CTX_get_max_proto_version(ctx));
    out_int(K("ssl.min_proto"), SSL_get_min_proto_version(ssl));
    out_int(K("ssl.max_proto"), SSL_get_max_proto_version(ssl));
    SSL_free(ssl);
    SSL_CTX_free(ctx);

#undef K
}

int main(void)
{
    const SSL_METHOD *m;
    SSL_CTX *ctx;
    SSL *ssl;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ----------------------------------------------------------------------------------------
     * A. Every constructor, and the context/connection/versions each installs.
     * -------------------------------------------------------------------------------------- */
    probe_meth("TLS_method", TLS_method);
    probe_meth("TLS_server_method", TLS_server_method);
    probe_meth("TLS_client_method", TLS_client_method);
    probe_meth("TLSv1_2_method", TLSv1_2_method);
    probe_meth("TLSv1_2_server_method", TLSv1_2_server_method);
    probe_meth("TLSv1_2_client_method", TLSv1_2_client_method);
    probe_meth("TLSv1_1_method", TLSv1_1_method);
    probe_meth("TLSv1_1_server_method", TLSv1_1_server_method);
    probe_meth("TLSv1_1_client_method", TLSv1_1_client_method);
    probe_meth("TLSv1_method", TLSv1_method);
    probe_meth("TLSv1_server_method", TLSv1_server_method);
    probe_meth("TLSv1_client_method", TLSv1_client_method);
    probe_meth("DTLS_method", DTLS_method);
    probe_meth("DTLS_server_method", DTLS_server_method);
    probe_meth("DTLS_client_method", DTLS_client_method);
    probe_meth("DTLSv1_2_method", DTLSv1_2_method);
    probe_meth("DTLSv1_2_server_method", DTLSv1_2_server_method);
    probe_meth("DTLSv1_2_client_method", DTLSv1_2_client_method);
    probe_meth("DTLSv1_method", DTLSv1_method);
    probe_meth("DTLSv1_server_method", DTLSv1_server_method);
    probe_meth("DTLSv1_client_method", DTLSv1_client_method);

    /* ----------------------------------------------------------------------------------------
     * B. The refusal arms.
     * -------------------------------------------------------------------------------------- */
    out_int("null.ctx_new_refused", SSL_CTX_new(NULL) == NULL);
    out_int("null.ssl_new_refused", SSL_new(NULL) == NULL);
    out_int("null.ctx_get_min_proto", SSL_CTX_get_min_proto_version(NULL));
    out_int("null.ctx_get_max_proto", SSL_CTX_get_max_proto_version(NULL));
    out_int("null.group_name", SSL_get0_group_name(NULL) == NULL);

    /* ----------------------------------------------------------------------------------------
     * C. The group-name accessors over a fixed TLS_method connection, unknown arms only.
     * -------------------------------------------------------------------------------------- */
    m = TLS_method();
    ctx = SSL_CTX_new(m);
    ssl = SSL_new(ctx);
    out_int("group.unknown_nid.null", SSL_group_to_name(ssl, 0) == NULL);
    out_int("group.bad_nid.null", SSL_group_to_name(ssl, 999999) == NULL);
    /* `TLSEXT_nid_unknown` (0x1000000) | an unknown group id; the authority also misses. */
    out_int("group.unknown_raw.null", SSL_group_to_name(ssl, 0x1000000 | 0x1234) == NULL);

    /* ----------------------------------------------------------------------------------------
     * D. The ticket-key callback installer: set, then re-set to NULL. No getter exists.
     * -------------------------------------------------------------------------------------- */
    out_int("ticket_evp.set", SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, ticket_key_evp_cb));
    out_int("ticket_evp.clear", SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, NULL));

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
