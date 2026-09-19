/*
 * The internal sub-structures the provider cipher contexts embed, measured for the same reason:
 * each is part of an allocation request. `XTS128_CONTEXT` and `OCB128_CONTEXT` live in
 * `include/crypto/` (modes headers), `SIV128_CONTEXT` in `include/crypto/siv128.h`, and
 * `PROV_CCM_CTX` in `prov/ciphercommon_ccm.h`.
 */
#include <stdio.h>
#include "prov/ciphercommon.h"
#include "prov/ciphercommon_ccm.h"
#include "cipher_aes_xts.h"
#include "cipher_aes_ocb.h"
#include "cipher_aes_ccm.h"

int main(void)
{
    printf("sizeof(XTS128_CONTEXT)=%zu\n", sizeof(XTS128_CONTEXT));
    printf("sizeof(OCB128_CONTEXT)=%zu\n", sizeof(OCB128_CONTEXT));
    printf("sizeof(PROV_CCM_CTX)=%zu\n", sizeof(PROV_CCM_CTX));
    printf("sizeof(SIV128_CONTEXT)=%zu\n", sizeof(struct siv128_context));
    printf("sizeof(AES_KEY)=%zu\n", sizeof(AES_KEY));
    /*
     * The OCB and CCM contexts field by field, because only the tail differs if a sub-structure is
     * modelled narrowly.
     */
    printf("PROV_AES_OCB_CTX ksenc=%zu ksdec=%zu ocb=%zu iv_state=%zu taglen=%zu\n",
           offsetof(PROV_AES_OCB_CTX, ksenc), offsetof(PROV_AES_OCB_CTX, ksdec),
           offsetof(PROV_AES_OCB_CTX, ocb), offsetof(PROV_AES_OCB_CTX, iv_state),
           offsetof(PROV_AES_OCB_CTX, taglen));
    printf("PROV_CCM_CTX=%zu PROV_AES_CCM_CTX ccm=%zu\n", sizeof(PROV_CCM_CTX),
           offsetof(PROV_AES_CCM_CTX, ccm));
    printf("PROV_AES_XTS_CTX ks1=%zu ks2=%zu xts=%zu\n",
           offsetof(PROV_AES_XTS_CTX, ks1), offsetof(PROV_AES_XTS_CTX, ks2),
           offsetof(PROV_AES_XTS_CTX, xts));
    return 0;
}
