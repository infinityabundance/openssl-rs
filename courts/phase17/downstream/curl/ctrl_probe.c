/*
 * Diagnostic: SSL_CTX_set_{min,max}_proto_version return values, candidate vs authority.
 *
 * curl's ossl_set_ssl_version_min_max() treats a 0 return from either call as fatal
 * (CURLE_SSL_CONNECT_ERROR, surfaced with no failf text as "(35) SSL connect error").
 * This one-screen probe prints the return of both calls and the value read back, so the
 * divergence is visible without a network.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <openssl/ssl.h>

int main(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());

    printf("ctx.nonnull=%d\n", ctx != NULL);
    printf("set_min_tls12=%d\n", SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION));
    printf("get_min=%d\n", SSL_CTX_get_min_proto_version(ctx));
    printf("set_max_zero=%d\n", SSL_CTX_set_max_proto_version(ctx, 0));
    printf("get_max=%d\n", SSL_CTX_get_max_proto_version(ctx));
    printf("ctrl_min_direct=%ld\n",
           SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, NULL));
    SSL_CTX_free(ctx);
    return 0;
}
