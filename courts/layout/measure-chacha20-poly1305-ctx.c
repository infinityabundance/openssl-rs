// Layout measurement for the `ChaCha20-Poly1305` provider context.
//
// `PROV_CHACHA20_POLY1305_CTX` is allocated by the provider with `OPENSSL_zalloc(sizeof(*ctx))`,
// so its size is what an application's `CRYPTO_set_mem_functions` allocator receives as `num`.
// Its offsets are what the hw vtable's `aead_cipher`/`initiv`/`tls_init`/`tls_iv_set_fixed`
// functions cast a `PROV_CIPHER_CTX *` back onto, so every one of them is contract.
//
// The member set matters twice over: the two bitfields `aad:1` and `mac_inited:1` are a single
// `unsigned int` lane in the authority, and `POLY1305` is a `struct poly1305_context` whose
// `double opaque[24]` forces eight-byte alignment on the whole tail. Neither is visible from the
// declaration alone at the byte level the provider's allocator sees.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include "prov/ciphercommon.h"
#include "cipher_chacha20_poly1305.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-18s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(PROV_CHACHA20_POLY1305_CTX);
    ALIGN(PROV_CHACHA20_POLY1305_CTX);
    OFF(PROV_CHACHA20_POLY1305_CTX, base);
    OFF(PROV_CHACHA20_POLY1305_CTX, chacha);
    OFF(PROV_CHACHA20_POLY1305_CTX, poly1305);
    OFF(PROV_CHACHA20_POLY1305_CTX, nonce);
    OFF(PROV_CHACHA20_POLY1305_CTX, tag);
    OFF(PROV_CHACHA20_POLY1305_CTX, tls_aad);
    OFF(PROV_CHACHA20_POLY1305_CTX, len);
    OFF(PROV_CHACHA20_POLY1305_CTX, tag_len);
    OFF(PROV_CHACHA20_POLY1305_CTX, tls_payload_length);
    OFF(PROV_CHACHA20_POLY1305_CTX, tls_aad_pad_sz);

    SHOW(PROV_CHACHA20_CTX);
    SHOW(POLY1305);
    ALIGN(POLY1305);
    SHOW(PROV_CIPHER_HW_CHACHA20_POLY1305);
    return 0;
}
