/*
 * Oracle for the `ChaCha20-Poly1305` hw vtable.
 *
 * `ossl_prov_cipher_hw_chacha20_poly1305()` has external linkage but no dynamic symbol, so it is
 * reachable only by linking the pinned **static** archive -- the same device `oracle-polyval.c`
 * uses. What it settles is a claim that cannot be read off the initialiser with any confidence:
 *
 *   static const PROV_CIPHER_HW_CHACHA20_POLY1305 chacha20poly1305_hw = {
 *       { chacha20_poly1305_initkey, NULL },     <-- brace elision over { init, cipher, copyctx }
 *       chacha20_poly1305_aead_cipher, ...
 *   };
 *
 * The inner brace supplies `init` and `cipher`; `copyctx` is elided. So `base.cipher` is a **null
 * function pointer**, unlike every other cipher row this crate transcribes, and the Rust
 * representation has to say so rather than store a fabricated address. `base.cipher` is never
 * called: the row's own `aead_cipher` reaches its ChaCha20 through `ctx->chacha.base.hw->cipher`,
 * which `ossl_chacha20_initctx` installs. Byte-identical brace elision is easy to misread, so this
 * prints what the compiler actually built.
 *
 * It also records the order of the extended vtable's four members, which is what ties the Rust
 * field order to `cipher_chacha20_poly1305.h`'s declaration rather than to the initialiser's
 * textual order.
 *
 * Build (needs the static archive, so the include set is the build tree's plus the source tree's):
 *   B=forensics/authorities/build/openssl-3.6.4-production
 *   S=forensics/authorities/src/openssl-3.6.4
 *   clang -std=c11 -I $B/include -I $B -I $B/providers/implementations/include \
 *     -I $B/providers/common/include -I $S -I $S/crypto -I $S/include \
 *     -I $S/providers/implementations/include -I $S/providers/common/include \
 *     -I $S/providers/implementations/ciphers -I $S/providers/fips/include \
 *     -o /tmp/oracle courts/layout/oracle-chacha20-poly1305-hw.c $B/libcrypto.a -lpthread -ldl
 */
#include <stdio.h>
#include <stddef.h>

#include "prov/ciphercommon.h"
#include "cipher_chacha20_poly1305.h"

static const char *yesno(const void *p)
{
    return p == NULL ? "NULL" : "non-null";
}

/* The four members after the base, in the header's declaration order. Four distinct non-null
 * pointers is the closest a program outside the translation unit can get to identifying them, and
 * it is enough to rule out two fields sharing one initialiser. The comparisons go through
 * `void (*)(void)` because the four have four different function types. */
int main(void)
{
    const PROV_CIPHER_HW_CHACHA20_POLY1305 *hw =
        (const PROV_CIPHER_HW_CHACHA20_POLY1305 *)
            ossl_prov_cipher_hw_chacha20_poly1305(256);

    printf("sizeof(PROV_CIPHER_HW_CHACHA20_POLY1305)=%zu\n", sizeof(*hw));
    printf("offsetof(base)=%zu\n", offsetof(PROV_CIPHER_HW_CHACHA20_POLY1305, base));
    printf("offsetof(aead_cipher)=%zu\n",
           offsetof(PROV_CIPHER_HW_CHACHA20_POLY1305, aead_cipher));
    printf("offsetof(initiv)=%zu\n", offsetof(PROV_CIPHER_HW_CHACHA20_POLY1305, initiv));
    printf("offsetof(tls_init)=%zu\n",
           offsetof(PROV_CIPHER_HW_CHACHA20_POLY1305, tls_init));
    printf("offsetof(tls_iv_set_fixed)=%zu\n",
           offsetof(PROV_CIPHER_HW_CHACHA20_POLY1305, tls_iv_set_fixed));
    printf("base.init=%s\n", yesno((const void *)hw->base.init));
    printf("base.cipher=%s\n", yesno((const void *)hw->base.cipher));
    printf("base.copyctx=%s\n", yesno((const void *)hw->base.copyctx));
    printf("aead_cipher=%s\n", yesno((const void *)hw->aead_cipher));
    printf("initiv=%s\n", yesno((const void *)hw->initiv));
    printf("tls_init=%s\n", yesno((const void *)hw->tls_init));
    printf("tls_iv_set_fixed=%s\n", yesno((const void *)hw->tls_iv_set_fixed));
    printf("four_members_distinct=%d\n",
           (void (*)(void))hw->aead_cipher != (void (*)(void))hw->initiv
               && (void (*)(void))hw->initiv != (void (*)(void))hw->tls_init
               && (void (*)(void))hw->tls_init != (void (*)(void))hw->tls_iv_set_fixed
               && (void (*)(void))hw->aead_cipher != (void (*)(void))hw->tls_init
               && (void (*)(void))hw->aead_cipher != (void (*)(void))hw->tls_iv_set_fixed
               && (void (*)(void))hw->initiv != (void (*)(void))hw->tls_iv_set_fixed);
    /* The selector ignores its argument, as `cipher_chacha20_poly1305_hw.c`'s last function shows. */
    printf("selector_ignores_keybits=%d\n",
           ossl_prov_cipher_hw_chacha20_poly1305(0)
               == ossl_prov_cipher_hw_chacha20_poly1305(256));
    return 0;
}
