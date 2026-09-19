/*
 * A one-off measuring program for every landed provider cipher context's size and layout, compiled
 * against the pinned authority's own internal headers. The allocation request is what a
 * `CRYPTO_set_mem_functions` application's allocator receives, so each of these numbers is contract
 * (D264's rule). `court/measure-union-align.c` asked the same question for the key structs alone.
 */
#include <stdio.h>
#include "prov/ciphercommon.h"
#include "cipher_aes.h"
#include "cipher_camellia.h"
#include "cipher_tdes.h"
#include "cipher_aes_xts.h"
#include "cipher_aes_ocb.h"
#include "cipher_aes_ccm.h"
#include "cipher_aes_siv.h"
#include "cipher_chacha20.h"
#include "cipher_sm4.h"
#include "cipher_aria.h"

int main(void)
{
    printf("PROV_CIPHER_CTX %zu\n", sizeof(PROV_CIPHER_CTX));
    printf("PROV_AES_CTX %zu\n", sizeof(PROV_AES_CTX));
    printf("PROV_CAMELLIA_CTX %zu\n", sizeof(PROV_CAMELLIA_CTX));
    printf("PROV_TDES_CTX %zu\n", sizeof(PROV_TDES_CTX));
    printf("PROV_AES_XTS_CTX %zu\n", sizeof(PROV_AES_XTS_CTX));
    printf("PROV_AES_OCB_CTX %zu\n", sizeof(PROV_AES_OCB_CTX));
    printf("PROV_AES_CCM_CTX %zu\n", sizeof(PROV_AES_CCM_CTX));
    printf("PROV_AES_SIV_CTX %zu\n", sizeof(PROV_AES_SIV_CTX));
    printf("PROV_CHACHA20_CTX %zu\n", sizeof(PROV_CHACHA20_CTX));
    printf("PROV_SM4_CTX %zu\n", sizeof(PROV_SM4_CTX));
    printf("PROV_ARIA_CTX %zu\n", sizeof(PROV_ARIA_CTX));
    /* the `ks` offsets, which the hw casts depend on */
    printf("off PROV_AES_CTX.ks %zu\n", offsetof(PROV_AES_CTX, ks));
    printf("off PROV_CAMELLIA_CTX.ks %zu\n", offsetof(PROV_CAMELLIA_CTX, ks));
    printf("off PROV_TDES_CTX.tks %zu\n", offsetof(PROV_TDES_CTX, tks));
    printf("off PROV_ARIA_CTX.ks %zu\n", offsetof(PROV_ARIA_CTX, ks));
    return 0;
}
