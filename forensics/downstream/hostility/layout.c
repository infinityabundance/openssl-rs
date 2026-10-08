/*
 * 24.10 hostility probe: **public-layout assumptions** — the version macros a consumer compiles
 * against, the accessor-based (never field-based) read of an opaque object's state, and an
 * `OSSL_PARAM` construction. It proves the public headers' compile-time and runtime layout contract
 * actually holds for the subject it was built against.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/params.h>

int main(void)
{
    hostility_banner("layout");
    printf("ver_major=%d\n", OPENSSL_VERSION_MAJOR);
    printf("ver_minor=%d\n", OPENSSL_VERSION_MINOR);
    printf("ver_patch=%d\n", OPENSSL_VERSION_PATCH);
    printf("ver_number=%lu\n", (unsigned long)OPENSSL_VERSION_NUMBER);

    X509 *x = X509_new();
    if (x == NULL)
        hostility_fail("X509_new");
    X509_set_version(x, 2);
    printf("x509_version=%ld\n", X509_get_version(x));
    const ASN1_TIME *nb = X509_get0_notBefore(x);
    printf("notbefore_set=%d\n", nb != NULL);
    X509_free(x);

    OSSL_PARAM p = OSSL_PARAM_construct_utf8_string("hostility", (char *)"1", 0);
    printf("param_key=%s\n", p.key != NULL ? p.key : "(null)");
    hostility_ok();
    return 0;
}
