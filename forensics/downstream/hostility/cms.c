/*
 * 24.10 hostility probe: **CMS** — sign a content buffer with a freshly generated key and self-signed
 * certificate, DER-encode the CMS ContentInfo, reparse it, and verify the detached signature through
 * `CMS_verify` against a store holding the signer. It exercises the CMS/S-MIME cryptographic-message
 * surface a mail or content family relies on.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/cms.h>

static const char *CONTENT = "hostility cms content\n";

int main(void)
{
    hostility_banner("cms");
    EVP_PKEY *k = hostility_keygen(1024);
    if (k == NULL)
        hostility_fail("EVP_PKEY_Q_keygen");
    X509 *x = hostility_selfsigned(k, "hostility-cms");
    if (x == NULL)
        hostility_fail("self-signed cert");

    BIO *in = BIO_new_mem_buf(CONTENT, -1);
    CMS_ContentInfo *ci = CMS_sign(x, k, NULL, in, CMS_BINARY | CMS_DETACHED);
    if (ci == NULL)
        hostility_fail("CMS_sign");

    unsigned char *der = NULL;
    int n = i2d_CMS_ContentInfo(ci, &der);
    if (n <= 0 || der == NULL)
        hostility_fail("i2d_CMS_ContentInfo");
    printf("cms_der_len=%d\n", n);
    CMS_ContentInfo_free(ci);
    BIO_free(in);

    const unsigned char *pp = der;
    CMS_ContentInfo *ci2 = d2i_CMS_ContentInfo(NULL, &pp, n);
    if (ci2 == NULL)
        hostility_fail("d2i_CMS_ContentInfo");

    X509_STORE *store = X509_STORE_new();
    if (store == NULL || !X509_STORE_add_cert(store, x))
        hostility_fail("X509_STORE_add_cert");
    BIO *out = BIO_new(BIO_s_mem());
    STACK_OF(X509) *certs = sk_X509_new_null();
    sk_X509_push(certs, x);
    /* CMS_sign produced a detached signature over the content; verify it against the content. */
    BIO *detached = BIO_new_mem_buf(CONTENT, -1);
    int ok = CMS_verify(ci2, certs, store, detached, out, CMS_BINARY | CMS_DETACHED);
    printf("cms_verify=%d\n", ok);
    BIO_free(detached);
    sk_X509_free(certs);
    BIO_free(out);
    X509_STORE_free(store);
    CMS_ContentInfo_free(ci2);
    OPENSSL_free(der);
    X509_free(x);
    EVP_PKEY_free(k);
    if (!ok)
        hostility_fail("CMS_verify");
    hostility_ok();
    return 0;
}
