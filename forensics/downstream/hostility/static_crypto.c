/*
 * 24.10 hostility probe: **static linkage** — the same digest/BIGNUM path as the shared probes, but
 * linked against the subject's `libcrypto.a` with **no** OpenSSL `DT_NEEDED`. The enabled-path proof
 * for a static build is different: the probe is compiled against the subject's static archive (whose
 * path and digest the court records) and links no OpenSSL shared object at all.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/bn.h>

int main(void)
{
    hostility_banner("static");

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (c == NULL)
        hostility_fail("EVP_MD_CTX_new");
    if (!EVP_DigestInit_ex(c, EVP_sha256(), NULL))
        hostility_fail("EVP_DigestInit_ex");
    EVP_DigestUpdate(c, "static", 6);
    EVP_DigestFinal_ex(c, md, &len);
    EVP_MD_CTX_free(c);
    printf("digest_len=%u\n", len);

    BIGNUM *b = BN_new();
    if (b == NULL)
        hostility_fail("BN_new");
    if (!BN_set_word(b, 65537))
        hostility_fail("BN_set_word");
    char *bh = BN_bn2hex(b);
    printf("bn_hex=%s\n", bh != NULL ? bh : "(null)");

    char *hx = OPENSSL_buf2hexstr(md, (long)len);
    printf("buf2hex_nonempty=%d\n", hx != NULL);

    OPENSSL_free(hx);
    OPENSSL_free(bh);
    BN_free(b);
    hostility_ok();
    return 0;
}
