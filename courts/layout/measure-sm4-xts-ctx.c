/*
 * A one-off measuring program for the `SM4-XTS` row's context, compiled against the pinned
 * authority's own internal headers. `cipher_sm4_xts.h` generates `OSSL_xts_stream_fn` from
 * `PROV_CIPHER_FUNC` with an `SM4_KEY` in its signature, and `cipher_aes_xts.h` generates the
 * **same typedef name** with an `AES_KEY` -- so the two headers cannot be included together and
 * this is a separate program from `measure-provider-ctxs.c`.
 */
#include <stdio.h>
#include "prov/ciphercommon.h"
#include "cipher_sm4_xts.h"

int main(void)
{
    printf("sizeof(PROV_SM4_XTS_CTX)=%zu\n", sizeof(PROV_SM4_XTS_CTX));
    printf("alignof(PROV_SM4_XTS_CTX)=%zu\n", _Alignof(PROV_SM4_XTS_CTX));
    printf("offsetof(ks1)=%zu\n", offsetof(PROV_SM4_XTS_CTX, ks1));
    printf("offsetof(ks2)=%zu\n", offsetof(PROV_SM4_XTS_CTX, ks2));
    printf("offsetof(xts_standard)=%zu\n", offsetof(PROV_SM4_XTS_CTX, xts_standard));
    printf("offsetof(xts)=%zu\n", offsetof(PROV_SM4_XTS_CTX, xts));
    printf("offsetof(stream_gb)=%zu\n", offsetof(PROV_SM4_XTS_CTX, stream_gb));
    printf("offsetof(stream)=%zu\n", offsetof(PROV_SM4_XTS_CTX, stream));
    printf("sizeof(SM4_KEY)=%zu\n", sizeof(SM4_KEY));
    printf("sizeof(XTS128_CONTEXT)=%zu\n", sizeof(XTS128_CONTEXT));
    return 0;
}
