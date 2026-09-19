// Layout measurement for the AES-GCM-SIV provider context.
//
// `PROV_AES_GCM_SIV_CTX` is allocated by the provider with `OPENSSL_zalloc(sizeof(*ctx))`, so its
// size is what an application's `CRYPTO_set_mem_functions` allocator receives as `num`. Its
// `Htable` member is a `u128[16]`, whose sixteen-byte alignment is what puts a gap between the
// trailing `nonce` and the table -- a gap no declaration states and only the compiler knows.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include "prov/ciphercommon.h"
#include "crypto/aes_platform.h"
#include "cipher_aes_gcm_siv.h"

#define SHOW(T) printf("sizeof(%-28s) = %zu\n", #T, sizeof(T))
#define OFF(T, m) printf("offsetof(%-24s, %-18s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(PROV_AES_GCM_SIV_CTX);
    SHOW(PROV_CIPHER_HW_AES_GCM_SIV);
    OFF(PROV_AES_GCM_SIV_CTX, ecb_ctx);
    OFF(PROV_AES_GCM_SIV_CTX, hw);
    OFF(PROV_AES_GCM_SIV_CTX, aad);
    OFF(PROV_AES_GCM_SIV_CTX, libctx);
    OFF(PROV_AES_GCM_SIV_CTX, provctx);
    OFF(PROV_AES_GCM_SIV_CTX, aad_len);
    OFF(PROV_AES_GCM_SIV_CTX, key_len);
    OFF(PROV_AES_GCM_SIV_CTX, key_gen_key);
    OFF(PROV_AES_GCM_SIV_CTX, msg_enc_key);
    OFF(PROV_AES_GCM_SIV_CTX, msg_auth_key);
    OFF(PROV_AES_GCM_SIV_CTX, tag);
    OFF(PROV_AES_GCM_SIV_CTX, user_tag);
    OFF(PROV_AES_GCM_SIV_CTX, nonce);
    OFF(PROV_AES_GCM_SIV_CTX, Htable);
    printf("alignof(PROV_AES_GCM_SIV_CTX) = %zu\n", _Alignof(PROV_AES_GCM_SIV_CTX));
    printf("alignof(u128) = %zu  sizeof(u128) = %zu\n", _Alignof(u128), sizeof(u128));
    return 0;
}
