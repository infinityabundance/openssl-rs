/*
 * openssl-rs — Phase 17 downstream (nginx): minimal, focused ABI probe.
 *
 * nginx treats these two setters as booleans and warns (disabling SNI / session tickets) when
 * they return 0. This probe prints the actual return values from whichever libssl it is linked
 * against, so the candidate's behaviour can be compared directly with the authority's.
 *
 * Build (inside the court):
 *   gcc -I<prefix>/include -o probe probe.c -L<prefix>/lib -Wl,-rpath,<prefix>/lib -lssl -lcrypto
 */
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static int sni_cb(SSL *s, int *al, void *arg)
{
    (void) s; (void) al; (void) arg;
    return SSL_TLSEXT_ERR_OK;
}

static int ticket_cb(SSL *s, unsigned char *name, unsigned char *iv,
                     EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
    (void) s; (void) name; (void) iv; (void) ctx; (void) hctx; (void) enc;
    return 0;
}

int main(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        printf("SSL_CTX_new failed\n");
        return 2;
    }

    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("SSL_CTX_set_tlsext_servername_callback = %d (real OpenSSL: 1)\n",
           SSL_CTX_set_tlsext_servername_callback(ctx, sni_cb));
    printf("SSL_CTX_set_tlsext_ticket_key_cb         = %d (real OpenSSL: 1)\n",
           SSL_CTX_set_tlsext_ticket_key_cb(ctx, ticket_cb));

    SSL_CTX_free(ctx);
    return 0;
}
