/*
 * A one-off measuring program for the `ChaCha20` row's context sizes, compiled against the pinned
 * authority's own internal headers. Recorded because the numbers a `CRYPTO_set_mem_functions`
 * application sees are contract, and the only honest source for them is the authority's compiler.
 */
#include <stdio.h>
#include "prov/ciphercommon.h"
#include "cipher_chacha20.h"

int main(void)
{
    printf("sizeof(PROV_CIPHER_CTX)=%zu\n", sizeof(PROV_CIPHER_CTX));
    printf("alignof(PROV_CIPHER_CTX)=%zu\n", _Alignof(PROV_CIPHER_CTX));
    printf("sizeof(PROV_CHACHA20_CTX)=%zu\n", sizeof(PROV_CHACHA20_CTX));
    printf("alignof(PROV_CHACHA20_CTX)=%zu\n", _Alignof(PROV_CHACHA20_CTX));
    printf("offsetof(PROV_CHACHA20_CTX,key)=%zu\n", offsetof(PROV_CHACHA20_CTX, key));
    printf("offsetof(PROV_CHACHA20_CTX,counter)=%zu\n", offsetof(PROV_CHACHA20_CTX, counter));
    printf("offsetof(PROV_CHACHA20_CTX,buf)=%zu\n", offsetof(PROV_CHACHA20_CTX, buf));
    printf("offsetof(PROV_CHACHA20_CTX,partial_len)=%zu\n",
           offsetof(PROV_CHACHA20_CTX, partial_len));
    printf("sizeof(PROV_CIPHER_HW_CHACHA20)=%zu\n", sizeof(PROV_CIPHER_HW_CHACHA20));
    return 0;
}
