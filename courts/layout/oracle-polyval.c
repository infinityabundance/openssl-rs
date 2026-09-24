// Oracle for the authority's POLYVAL helpers.
//
// `ossl_polyval_ghash_init` and `ossl_polyval_ghash_hash` are internal functions with external
// linkage, so they are present in the pinned static archive even though they are absent from the
// shared object's dynamic symbol table. Linking this program against `libcrypto.a` therefore gives
// a direct oracle for the POLYVAL bridging in `src/provider/cipher.rs` -- which the differential
// court can only reach through a whole AES-GCM-SIV record, where a byte-order error in either the
// key setup or the accumulator looks the same as an error anywhere else in the construction.
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef unsigned __int128 u128;

extern void ossl_polyval_ghash_init(u128 Htable[16], const uint64_t H[2]);
extern void ossl_polyval_ghash_hash(const u128 Htable[16], uint8_t *tag, const uint8_t *inp,
                                    size_t len);

static void hex(const char *name, const uint8_t *p, size_t n)
{
    size_t i;
    printf("%s=", name);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

int main(void)
{
    // Two cases, so a bug that only shows up with a nonzero accumulator is visible too.
    static const uint8_t h_key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    static const uint8_t block1[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t block2[16] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    u128 table[16];
    uint8_t tag[16];
    uint8_t two[32];

    ossl_polyval_ghash_init(table, (const uint64_t *)h_key);

    memset(tag, 0, sizeof(tag));
    ossl_polyval_ghash_hash(table, tag, block1, sizeof(block1));
    hex("polyval.one", tag, sizeof(tag));

    memcpy(two, block1, 16);
    memcpy(two + 16, block2, 16);
    memset(tag, 0, sizeof(tag));
    ossl_polyval_ghash_hash(table, tag, two, sizeof(two));
    hex("polyval.two", tag, sizeof(tag));

    // A nonzero starting accumulator, which is the shape a second `_hash` call makes.
    memset(tag, 0, sizeof(tag));
    ossl_polyval_ghash_hash(table, tag, block1, sizeof(block1));
    ossl_polyval_ghash_hash(table, tag, block2, sizeof(block2));
    hex("polyval.split", tag, sizeof(tag));

    return 0;
}
