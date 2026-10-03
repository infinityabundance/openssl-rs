/*
 * rt_ssl_init_probe.c -- RT-SSL-INIT: the Phase-14.10 init, error and QUIC bridge, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed string -- never an address, never a clock, never the
 * error queue, never a network.
 *
 * ## What this probe drives
 *
 *   * `OPENSSL_init_ssl` with fixed option words -- 0, the SSL-strings bit, the no-config bit, the
 *     config bit and the no-load-SSL-strings bit, repeated. The authority's own `stopped` refusal
 *     (`ssl_init.c:50`) is dead code -- it is never assigned in the unit -- so the function has no
 *     reachable refusal arm on either side and every arm here is a return arm;
 *   * `ERR_load_SSL_strings` on the first and a repeated call;
 *   * the QUIC TLS accessors over a fixed, incomplete `OSSL_DISPATCH` table: `SSL_set_quic_tls_cbs`
 *     over NULL, a DTLS connection, an empty table and a partial table (all refusals);
 *     `SSL_set_quic_tls_transport_params` and `SSL_set_quic_tls_early_data_enabled` over NULL, a
 *     DTLS connection and a fresh TLS connection (the NULL-`qtls` refusals); and
 *     `SSL_inject_net_dgram` over NULL, a DTLS connection and a TLS connection.
 *
 * ## Arms that are deliberately absent
 *
 * The complete-dispatch arm of `SSL_set_quic_tls_cbs` is not driven: it reaches
 * `ossl_quic_tls_new`, which is Phase 15's, and `src/ssl/quic/quic_tls_api.rs` records that
 * reduction. `OPENSSL_init_ssl` is not called with a NULL-terminated dispatch table, so no
 * function-pointer call is observable. No handshake, no socket and no wall clock move an answer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static int dummy_cb(void)
{
    return 1;
}

int main(void)
{
    SSL_CTX *tls_ctx, *dtls_ctx;
    SSL *tls, *dtls;
    const unsigned char params[3] = { 1, 2, 3 };

    static const OSSL_DISPATCH empty_dis[] = { OSSL_DISPATCH_END };
    static const OSSL_DISPATCH partial_dis[] = {
        { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))dummy_cb },
        { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))dummy_cb },
        OSSL_DISPATCH_END
    };

    tls_ctx = SSL_CTX_new(TLS_method());
    dtls_ctx = SSL_CTX_new(DTLS_method());
    tls = SSL_new(tls_ctx);
    dtls = SSL_new(dtls_ctx);
    out_int("ctx.tls.nonnull", tls_ctx != NULL);
    out_int("ctx.dtls.nonnull", dtls_ctx != NULL);
    out_int("tls.nonnull", tls != NULL);
    out_int("dtls.nonnull", dtls != NULL);

    /* -----------------------------------------------------------------------------------------
     * A. OPENSSL_init_ssl.
     * --------------------------------------------------------------------------------------- */
    out_int("init_ssl.zero", OPENSSL_init_ssl(0, NULL));
    out_int("init_ssl.zero.again", OPENSSL_init_ssl(0, NULL));
    out_int("init_ssl.ssl_strings", OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL));
    out_int("init_ssl.no_load_config", OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL));
    out_int("init_ssl.load_config",
            OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_LOAD_SSL_STRINGS, NULL));
    out_int("init_ssl.no_load_ssl_strings",
            OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_SSL_STRINGS, NULL));

    /* -----------------------------------------------------------------------------------------
     * B. ERR_load_SSL_strings.
     * --------------------------------------------------------------------------------------- */
    out_int("err_load", ERR_load_SSL_strings());
    out_int("err_load.again", ERR_load_SSL_strings());

    /* -----------------------------------------------------------------------------------------
     * C. The QUIC TLS accessors.
     * --------------------------------------------------------------------------------------- */
    out_int("quic_cbs.null", SSL_set_quic_tls_cbs(NULL, partial_dis, NULL));
    out_int("quic_cbs.dtls", SSL_set_quic_tls_cbs(dtls, partial_dis, NULL));
    out_int("quic_cbs.empty", SSL_set_quic_tls_cbs(tls, empty_dis, NULL));
    out_int("quic_cbs.partial", SSL_set_quic_tls_cbs(tls, partial_dis, (void *)1));

    out_int("quic_transport.null", SSL_set_quic_tls_transport_params(NULL, params, 3));
    out_int("quic_transport.dtls", SSL_set_quic_tls_transport_params(dtls, params, 3));
    out_int("quic_transport.tls", SSL_set_quic_tls_transport_params(tls, params, 3));

    out_int("quic_early_data.null", SSL_set_quic_tls_early_data_enabled(NULL, 1));
    out_int("quic_early_data.dtls", SSL_set_quic_tls_early_data_enabled(dtls, 1));
    out_int("quic_early_data.tls", SSL_set_quic_tls_early_data_enabled(tls, 1));

    out_int("inject.null", SSL_inject_net_dgram(NULL, params, 3, NULL, NULL));
    out_int("inject.dtls", SSL_inject_net_dgram(dtls, params, 3, NULL, NULL));
    out_int("inject.tls", SSL_inject_net_dgram(tls, params, 3, NULL, NULL));

    /* -----------------------------------------------------------------------------------------
     * D. Release.
     * --------------------------------------------------------------------------------------- */
    SSL_free(tls);
    SSL_free(dtls);
    SSL_CTX_free(tls_ctx);
    SSL_CTX_free(dtls_ctx);
    out_int("freed", 1);
    return 0;
}
