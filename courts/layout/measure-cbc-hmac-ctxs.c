// Layout measurement for the AES-CBC-HMAC-SHA provider contexts.
//
// The context sizes are contract: the provider allocates `sizeof(*ctx)` for the row and an
// application's `CRYPTO_set_mem_functions` allocator receives that byte count as `num`. The
// offsets are contract too: `aesni_cbc_hmac_sha1_cipher` casts a `PROV_CIPHER_CTX *` back onto
// `PROV_AES_HMAC_SHA_CTX *` and `PROV_AES_HMAC_SHA1_CTX *`.
//
// `-DAES_ASM` is how the pinned build compiles: `aes_platform.h:169-172` guards
// `AES_CBC_HMAC_SHA_CAPABLE`/`AESNI_CBC_HMAC_SHA_CAPABLE` on it, and the non-ETM rows *are*
// published on this host, which is the measurement that proves the guard is live here.
//
// The ETM contexts are deliberately absent: `AES_CBC_HMAC_SHA_ETM_CAPABLE` is aarch64-only
// (`aes_platform.h:114-121`), so on this profile the typedefs do not exist, no ETM row is
// published, and no ETM context is ever allocated. `cipher_aes_cbc_hmac_sha_etm.h:27-71` is the
// evidence.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include "prov/ciphercommon.h"
#include "crypto/aes_platform.h"
#include "cipher_aes_cbc_hmac_sha.h"

#define SHOW(T) printf("sizeof(%-28s) = %zu\n", #T, sizeof(T))
#define OFF(T, m) printf("offsetof(%-24s, %-18s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(PROV_AES_HMAC_SHA_CTX);
    SHOW(PROV_AES_HMAC_SHA1_CTX);
    SHOW(PROV_AES_HMAC_SHA256_CTX);
    SHOW(PROV_CIPHER_HW_AES_HMAC_SHA);
    SHOW(PROV_CIPHER_CTX);

    printf("--- non-ETM members ---\n");
    OFF(PROV_AES_HMAC_SHA_CTX, base);
    OFF(PROV_AES_HMAC_SHA_CTX, ks);
    OFF(PROV_AES_HMAC_SHA_CTX, payload_length);
    OFF(PROV_AES_HMAC_SHA_CTX, aux);
    OFF(PROV_AES_HMAC_SHA_CTX, hw);
    OFF(PROV_AES_HMAC_SHA_CTX, multiblock_interleave);
    OFF(PROV_AES_HMAC_SHA_CTX, multiblock_aad_packlen);
    OFF(PROV_AES_HMAC_SHA_CTX, multiblock_max_send_fragment);
    OFF(PROV_AES_HMAC_SHA_CTX, multiblock_encrypt_len);
    OFF(PROV_AES_HMAC_SHA_CTX, tls_aad_pad);
    OFF(PROV_AES_HMAC_SHA1_CTX, head);
    OFF(PROV_AES_HMAC_SHA1_CTX, tail);
    OFF(PROV_AES_HMAC_SHA1_CTX, md);
    OFF(PROV_AES_HMAC_SHA256_CTX, base_ctx);
    OFF(PROV_AES_HMAC_SHA256_CTX, head);
    OFF(PROV_AES_HMAC_SHA256_CTX, tail);
    OFF(PROV_AES_HMAC_SHA256_CTX, md);
    printf("sizeof(AES_KEY) = %zu\n", sizeof(AES_KEY));
    printf("sizeof(SHA_CTX) = %zu\n", sizeof(SHA_CTX));
    printf("sizeof(SHA256_CTX) = %zu\n", sizeof(SHA256_CTX));
    return 0;
}
