/*
 * A one-off measuring program for the union-alignment question: `OSSL_UNION_ALIGN` makes each
 * `{ OSSL_UNION_ALIGN; <ALG>_KEY ks; }` union eight-aligned, so a key struct whose size is not a
 * multiple of eight contributes tail padding that is part of the allocated object.
 */
#include <stdio.h>
#include "prov/ciphercommon.h"
#include "cipher_aes.h"
#include "cipher_camellia.h"
#include "cipher_sm4.h"
#include "cipher_aria.h"

int main(void)
{
    printf("sizeof(AES_KEY)=%zu align=%zu\n", sizeof(AES_KEY), _Alignof(AES_KEY));
    printf("sizeof(PROV_AES_CTX)=%zu align=%zu ks=%zu\n",
           sizeof(PROV_AES_CTX), _Alignof(PROV_AES_CTX), offsetof(PROV_AES_CTX, ks));
    printf("sizeof(CAMELLIA_KEY)=%zu align=%zu\n", sizeof(CAMELLIA_KEY), _Alignof(CAMELLIA_KEY));
    printf("sizeof(PROV_CAMELLIA_CTX)=%zu align=%zu ks=%zu\n",
           sizeof(PROV_CAMELLIA_CTX), _Alignof(PROV_CAMELLIA_CTX),
           offsetof(PROV_CAMELLIA_CTX, ks));
    printf("sizeof(SM4_KEY)=%zu align=%zu\n", sizeof(SM4_KEY), _Alignof(SM4_KEY));
    printf("sizeof(PROV_SM4_CTX)=%zu align=%zu ks=%zu\n",
           sizeof(PROV_SM4_CTX), _Alignof(PROV_SM4_CTX), offsetof(PROV_SM4_CTX, ks));
    printf("sizeof(ARIA_KEY)=%zu align=%zu\n", sizeof(ARIA_KEY), _Alignof(ARIA_KEY));
    printf("sizeof(PROV_ARIA_CTX)=%zu align=%zu ks=%zu\n",
           sizeof(PROV_ARIA_CTX), _Alignof(PROV_ARIA_CTX), offsetof(PROV_ARIA_CTX, ks));
    return 0;
}
