/*
 * 24.10 hostility probe: **PKCS#12** — create a PKCS#12 container over a freshly generated key and
 * self-signed certificate, DER-encode it, reparse it, and recover the key and certificate through
 * `PKCS12_parse`. It exercises the PKCS#12/PBE surface a keystore-consuming family relies on.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/pkcs12.h>

int main(void)
{
    hostility_banner("pkcs12");
    PKCS12_PBE_add();

    EVP_PKEY *k = hostility_keygen(1024);
    if (k == NULL)
        hostility_fail("EVP_PKEY_Q_keygen");
    X509 *x = hostility_selfsigned(k, "hostility-pkcs12");
    if (x == NULL)
        hostility_fail("self-signed cert");

    PKCS12 *p = PKCS12_create("hostility", "friendly", k, x, NULL, 0, 0, 0, 0, 0);
    if (p == NULL)
        hostility_fail("PKCS12_create");

    unsigned char *der = NULL;
    int n = i2d_PKCS12(p, &der);
    if (n <= 0 || der == NULL)
        hostility_fail("i2d_PKCS12");
    printf("pkcs12_der_len=%d\n", n);

    const unsigned char *pp = der;
    PKCS12 *p2 = d2i_PKCS12(NULL, &pp, n);
    if (p2 == NULL)
        hostility_fail("d2i_PKCS12");

    EVP_PKEY *k2 = NULL;
    X509 *x2 = NULL;
    STACK_OF(X509) *ca2 = NULL;
    if (!PKCS12_parse(p2, "hostility", &k2, &x2, &ca2))
        hostility_fail("PKCS12_parse");
    printf("parsed_key_bits=%d\n", EVP_PKEY_get_bits(k2));
    printf("parsed_cert=%d\n", x2 != NULL);

    EVP_PKEY_free(k2);
    X509_free(x2);
    sk_X509_pop_free(ca2, X509_free);
    PKCS12_free(p2);
    PKCS12_free(p);
    OPENSSL_free(der);
    X509_free(x);
    EVP_PKEY_free(k);
    hostility_ok();
    return 0;
}
