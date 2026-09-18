/*
 * openssl-rs — the differential cipher-mode probe (RT-CIPHER), first arm: the non-AEAD
 * `modes.h` helpers.
 *
 * This program is compiled **twice**, once against the admitted authority and once against
 * the candidate distribution shell, and the two `key=value` transcripts are diffed. It never
 * decides anything: a residual is a difference between two executions, so the expectation
 * cannot drift with the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * Why a probe-local block function is enough for this arm
 * -------------------------------------------------------
 * Every `CRYPTO_*` function in this arm is generic over a caller-supplied `block128_f` (or
 * `cbc128_f`/`ctr128_f`), so the transform can be observed on both sides before any cipher
 * has landed. The block function below is deterministic and depends only on the key byte, so
 * both compilations call the same sixteen-byte permutation and the only thing the diff can
 * see is the mode arithmetic. Once AES lands, the same observations are repeated with
 * `AES_encrypt` as the block function, so the mode functions are also exercised through the
 * cipher the corpus's mode vectors use.
 *
 * What it observes, per mode
 * --------------------------
 *   * the ciphertext, as hex, for an input that is one block plus a partial block, so the
 *     trailing arm is taken;
 *   * the IV write-back, as hex: the authority advances the IV through the caller's pointer
 *     and a transcription that copies it instead will differ here and nowhere else;
 *   * the `num` round trip (`*num` is both an input and an output of the feedback modes);
 *   * the `*num = -1` poison arm, which the authority takes when `*num < 0`;
 *   * `CRYPTO_cfb128_1_encrypt`'s bit-oriented length: one bit processed leaves the other
 *     seven bits of the destination byte untouched, and eight bits process one byte;
 *   * the CTS return value, which is the number of output bytes written.
 *
 * No address is ever printed, stdout is line-buffered, and no NULL-dereferencing entry point
 * is called.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/modes.h>

#define RT_KEY 0xa7u
#define RT_BLOCK 16u

static void rt_hex(const char *name, const unsigned char *p, size_t n)
{
    size_t i;

    printf("%s=", name);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void rt_hexf(const char *name, int which, const unsigned char *p, size_t n)
{
    char buf[64];

    snprintf(buf, sizeof(buf), "%s.%d", name, which);
    rt_hex(buf, p, n);
}

/* A probe-local block function: a sixteen-byte permutation that depends only on the key
 * byte, so both sides compute exactly the same "cipher" and only the mode differs. It is its
 * own inverse, which is what the CBC-decrypt and CTS-decrypt arms need. */
static void rt_block(const unsigned char *in, unsigned char *out, const void *key)
{
    const unsigned char k = *(const unsigned char *)key;
    unsigned char i;

    for (i = 0; i < RT_BLOCK; i++)
        out[i] = in[i] ^ (unsigned char)(k + i * 7u + 3u);
}

/* The probe-local `ctr128_f`: XOR `blocks` blocks with the keystream the block function
 * produces from a big-endian 32-bit counter in `ivec[12..16]`, without advancing `ivec`. */
static void rt_ctr32(const unsigned char *in, unsigned char *out, size_t blocks,
                     const void *key, const unsigned char ivec[16])
{
    unsigned char counter[16];
    unsigned char ks[16];
    size_t b, i;
    unsigned int ctr;

    memcpy(counter, ivec, 16);
    ctr = ((unsigned int)counter[12] << 24) | ((unsigned int)counter[13] << 16)
        | ((unsigned int)counter[14] << 8) | (unsigned int)counter[15];

    for (b = 0; b < blocks; b++) {
        rt_block(counter, ks, key);
        for (i = 0; i < 16; i++)
            out[b * 16 + i] = in[b * 16 + i] ^ ks[i];
        ctr++;
        counter[12] = (unsigned char)(ctr >> 24);
        counter[13] = (unsigned char)(ctr >> 16);
        counter[14] = (unsigned char)(ctr >> 8);
        counter[15] = (unsigned char)ctr;
    }
}

static void rt_cbc(const unsigned char *in, unsigned char *out, size_t len,
                   const void *key, unsigned char ivec[16], int enc)
{
    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec, rt_block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec, rt_block);
}

static void rt_fill(unsigned char *p, size_t n, unsigned int seed)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)((i * 13u + seed * 29u + 7u) & 0xffu);
}

/* The `block128_f` views of AES, so the generic mode functions are exercised through the
 * cipher the corpus's mode vectors use as well as through the probe-local permutation. */
static void rt_aes_block(const unsigned char *in, unsigned char *out, const void *key)
{
    AES_encrypt(in, out, (const AES_KEY *)key);
}

static void rt_aes_dec_block(const unsigned char *in, unsigned char *out, const void *key)
{
    AES_decrypt(in, out, (const AES_KEY *)key);
}

static void rt_aes(void)
{
    unsigned char key[32];
    unsigned char iv[64];
    unsigned char in[64];
    unsigned char out[96];
    unsigned char dec[64];
    AES_KEY enc, dck;
    int n;

    rt_fill(key, sizeof(key), 1);
    rt_fill(in, sizeof(in), 2);

    /* The schedule sizes are part of the ABI the caller allocates, so they are observed. */
    printf("aes.sizeof_key=%u\n", (unsigned)sizeof(AES_KEY));
    for (n = 0; n < 3; n++) {
        int bits = 128 + 64 * n;
        int rc;

        memset(&enc, 0, sizeof(enc));
        rc = AES_set_encrypt_key(key, bits, &enc);
        printf("aes.set_encrypt_key.%d=%d\n", bits, rc);
        printf("aes.rounds.%d=%d\n", bits, enc.rounds);
        rt_hexf("aes.rk.0", bits, (const unsigned char *)enc.rd_key, 16);
        rt_hexf("aes.rk.last", bits, (const unsigned char *)&enc.rd_key[4 * enc.rounds], 16);

        memset(&dck, 0, sizeof(dck));
        rc = AES_set_decrypt_key(key, bits, &dck);
        printf("aes.set_decrypt_key.%d=%d\n", bits, rc);
        rt_hexf("aes.drk.0", bits, (const unsigned char *)dck.rd_key, 16);
        rt_hexf("aes.drk.last", bits, (const unsigned char *)&dck.rd_key[4 * dck.rounds], 16);

        AES_encrypt(in, out, &enc);
        rt_hexf("aes.encrypt", bits, out, 16);
        AES_decrypt(out, dec, &dck);
        rt_hexf("aes.decrypt", bits, dec, 16);

        AES_ecb_encrypt(in, out, &enc, AES_ENCRYPT);
        rt_hexf("aes.ecb.enc", bits, out, 16);
        AES_ecb_encrypt(out, dec, &dck, AES_DECRYPT);
        rt_hexf("aes.ecb.dec", bits, dec, 16);
    }

    /* The invalid-bits arms return the authority's negative codes. */
    printf("aes.set_encrypt_key.bad=%d\n", AES_set_encrypt_key(key, 64, &enc));
    printf("aes.set_encrypt_key.null=%d\n", AES_set_encrypt_key(NULL, 128, &enc));

    /* CBC, out of place, with the advanced IV observed. */
    memset(&enc, 0, sizeof(enc));
    AES_set_encrypt_key(key, 128, &enc);
    memset(&dck, 0, sizeof(dck));
    AES_set_decrypt_key(key, 128, &dck);

    rt_fill(iv, 32, 3);
    memset(out, 0, sizeof(out));
    AES_cbc_encrypt(in, out, 33, &enc, iv, AES_ENCRYPT);
    rt_hex("aes.cbc.enc", out, 48);
    rt_hex("aes.cbc.enc.iv", iv, 16);

    {
        unsigned char iv2[16];
        rt_fill(iv2, 16, 3);
        memset(dec, 0, sizeof(dec));
        AES_cbc_encrypt(in, out, 48, &enc, iv2, AES_ENCRYPT);
        {
            unsigned char civ[16];
            memcpy(civ, iv2, 16);
            rt_fill(civ, 16, 3);
            AES_cbc_encrypt(out, dec, 48, &dck, civ, AES_DECRYPT);
            rt_hex("aes.cbc.roundtrip", dec, 48);
            rt_hex("aes.cbc.dec.iv", civ, 16);
        }
    }

    /* CFB-128 / CFB-8 / CFB-1 / OFB, with the `num` round trip. */
    {
        int num = 0;

        rt_fill(iv, 32, 4);
        memset(out, 0, sizeof(out));
        AES_cfb128_encrypt(in, out, 35, &enc, iv, &num, AES_ENCRYPT);
        rt_hex("aes.cfb128.enc", out, 35);
        rt_hex("aes.cfb128.iv", iv, 16);
        printf("aes.cfb128.num=%d\n", num);

        num = 0;
        rt_fill(iv, 32, 4);
        memset(out, 0, sizeof(out));
        AES_cfb128_encrypt(in, out, 35, &enc, iv, &num, AES_DECRYPT);
        rt_hex("aes.cfb128.dec", out, 35);

        num = 0;
        rt_fill(iv, 32, 4);
        memset(out, 0, sizeof(out));
        AES_cfb8_encrypt(in, out, 20, &enc, iv, &num, AES_ENCRYPT);
        rt_hex("aes.cfb8.enc", out, 20);
        rt_hex("aes.cfb8.iv", iv, 16);

        num = 0;
        rt_fill(iv, 32, 4);
        memset(out, 0x55, sizeof(out));
        AES_cfb1_encrypt(in, out, 9, &enc, iv, &num, AES_ENCRYPT);
        rt_hex("aes.cfb1.bits9", out, 2);

        num = 0;
        rt_fill(iv, 32, 4);
        memset(out, 0, sizeof(out));
        AES_ofb128_encrypt(in, out, 40, &enc, iv, &num);
        rt_hex("aes.ofb.enc", out, 40);
        rt_hex("aes.ofb.iv", iv, 16);
        printf("aes.ofb.num=%d\n", num);
    }

    /* IGE: the IV is two blocks, and the authority writes both back. */
    {
        unsigned char igev[32];
        unsigned char bigev[64];

        rt_fill(igev, sizeof(igev), 5);
        memset(out, 0, sizeof(out));
        AES_ige_encrypt(in, out, 64, &enc, igev, AES_ENCRYPT);
        rt_hex("aes.ige.enc", out, 64);
        rt_hex("aes.ige.enc.iv", igev, 32);
        AES_ige_encrypt(out, dec, 64, &dck, igev, AES_DECRYPT);
        rt_hex("aes.ige.dec", dec, 64);
        rt_hex("aes.ige.dec.iv", igev, 32);

        rt_fill(bigev, sizeof(bigev), 6);
        memset(out, 0, sizeof(out));
        AES_bi_ige_encrypt(in, out, 64, &enc, &enc, bigev, AES_ENCRYPT);
        rt_hex("aes.bi_ige.enc", out, 64);
        AES_bi_ige_encrypt(out, dec, 64, &dck, &dck, bigev, AES_DECRYPT);
        rt_hex("aes.bi_ige.dec", dec, 64);
    }

    /* Key wrap: RFC 3394's own vector, plus the non-multiple-of-8 and short-input refusals. */
    {
        static const unsigned char kek[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        static const unsigned char kd[16] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        AES_KEY wk, uk;
        unsigned char wrapped[64];
        unsigned char unwrapped[64];
        int m;

        memset(&wk, 0, sizeof(wk));
        AES_set_encrypt_key(kek, 128, &wk);
        memset(&uk, 0, sizeof(uk));
        AES_set_decrypt_key(kek, 128, &uk);

        memset(wrapped, 0, sizeof(wrapped));
        m = AES_wrap_key(&wk, NULL, wrapped, kd, 16);
        printf("aes.wrap.ret=%d\n", m);
        rt_hex("aes.wrap.ct", wrapped, 24);

        memset(unwrapped, 0, sizeof(unwrapped));
        m = AES_unwrap_key(&uk, NULL, unwrapped, wrapped, 24);
        printf("aes.unwrap.ret=%d\n", m);
        rt_hex("aes.unwrap.pt", unwrapped, 16);

        printf("aes.wrap.nonmultiple=%d\n", AES_wrap_key(&wk, NULL, wrapped, kd, 17));
        printf("aes.wrap.short=%d\n", AES_wrap_key(&wk, NULL, wrapped, kd, 8));
        printf("aes.unwrap.bad_iv=%d\n", AES_unwrap_key(&uk, kd, unwrapped, wrapped, 24));
    }

    /* An explicit IV is observed too, and must not be replaced by the default. */
    {
        static const unsigned char iv8[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        static const unsigned char kd[16] = { 0 };
        AES_KEY wk, uk;
        unsigned char wrapped[64];
        unsigned char unwrapped[16];

        memset(&wk, 0, sizeof(wk));
        AES_set_encrypt_key(key, 128, &wk);
        memset(&uk, 0, sizeof(uk));
        AES_set_decrypt_key(key, 128, &uk);
        memset(wrapped, 0, sizeof(wrapped));
        printf("aes.wrap.explicit_iv=%d\n", AES_wrap_key(&wk, iv8, wrapped, kd, 16));
        rt_hex("aes.wrap.explicit_iv.ct", wrapped, 24);
        printf("aes.unwrap.wrong_iv=%d\n", AES_unwrap_key(&uk, NULL, unwrapped, wrapped, 24));
    }

    printf("aes.options=%s\n", AES_options());
}

static void rt_modes_blocks(void)
{
    const unsigned char key = RT_KEY;
    unsigned char in[48];
    unsigned char out[64];
    unsigned char iv[16];
    unsigned char ecount[16];
    unsigned int num;

    rt_fill(in, sizeof(in), 1);

    /* ---- CBC encryption: a full block plus a partial one, so the tail arm is taken. ---- */
    rt_fill(iv, 16, 2);
    memset(out, 0, sizeof(out));
    CRYPTO_cbc128_encrypt(in, out, 33, &key, iv, rt_block);
    rt_hex("mode.cbc.enc.ct", out, 48);
    rt_hex("mode.cbc.enc.iv", iv, 16);

    /* ---- CBC decryption, out of place: the inverse of the same transform. ---- */
    rt_fill(iv, 16, 2);
    memset(out, 0, sizeof(out));
    CRYPTO_cbc128_decrypt(in, out, 33, &key, iv, rt_block);
    rt_hex("mode.cbc.dec.ct", out, 33);
    rt_hex("mode.cbc.dec.iv", iv, 16);

    /* ---- CBC decryption in place: the second arm of the same function. ---- */
    {
        unsigned char buf[48];

        memcpy(buf, in, sizeof(buf));
        rt_fill(iv, 16, 2);
        CRYPTO_cbc128_decrypt(buf, buf, 48, &key, iv, rt_block);
        rt_hex("mode.cbc.dec_inplace.ct", buf, 48);
        rt_hex("mode.cbc.dec_inplace.iv", iv, 16);
    }

    /* ---- CBC zero length: nothing is written and the IV does not move. ---- */
    rt_fill(iv, 16, 2);
    memset(out, 0xee, sizeof(out));
    CRYPTO_cbc128_encrypt(in, out, 0, &key, iv, rt_block);
    rt_hex("mode.cbc.zero.ct", out, 16);
    rt_hex("mode.cbc.zero.iv", iv, 16);

    /* ---- OFB: the IV is the keystream, so the plaintext XOR ciphertext is the keystream. ---- */
    rt_fill(iv, 16, 3);
    num = 0;
    memset(out, 0, sizeof(out));
    CRYPTO_ofb128_encrypt(in, out, 40, &key, iv, (int *)&num, rt_block);
    rt_hex("mode.ofb.ct", out, 40);
    rt_hex("mode.ofb.iv", iv, 16);
    num = 0;
    rt_fill(iv, 16, 3);
    memset(out, 0, sizeof(out));
    CRYPTO_ofb128_encrypt(in, out, 40, &key, iv, (int *)&num, rt_block);
    rt_hex("mode.ofb.ct2", out, 40);
    printf("mode.ofb.num=%u\n", (unsigned)num);

    /* ---- OFB poison arm: a negative incoming `num` is preserved as -1. ---- */
    num = 0xffffffffu;
    CRYPTO_ofb128_encrypt(in, out, 16, &key, iv, (int *)&num, rt_block);
    printf("mode.ofb.poison_num=%d\n", (int)num);

    /* ---- CFB-128 encryption and decryption, with a resumed `num`. ---- */
    rt_fill(iv, 16, 4);
    num = 5;
    memset(out, 0, sizeof(out));
    rt_fill(ecount, 16, 9);
    CRYPTO_cfb128_encrypt(in, out, 37, &key, iv, (int *)&num, 1, rt_block);
    rt_hex("mode.cfb128.enc.ct", out, 37);
    rt_hex("mode.cfb128.enc.iv", iv, 16);
    printf("mode.cfb128.enc.num=%u\n", (unsigned)num);

    rt_fill(iv, 16, 4);
    num = 5;
    memset(out, 0, sizeof(out));
    CRYPTO_cfb128_encrypt(in, out, 37, &key, iv, (int *)&num, 0, rt_block);
    rt_hex("mode.cfb128.dec.ct", out, 37);
    rt_hex("mode.cfb128.dec.iv", iv, 16);
    printf("mode.cfb128.dec.num=%u\n", (unsigned)num);

    /* ---- CFB poison arm. ---- */
    num = 0xffffffffu;
    rt_fill(iv, 16, 4);
    CRYPTO_cfb128_encrypt(in, out, 16, &key, iv, (int *)&num, 1, rt_block);
    printf("mode.cfb128.poison_num=%d\n", (int)num);

    /* ---- CFB-8: one byte at a time, MSB-first. ---- */
    rt_fill(iv, 16, 5);
    num = 0;
    memset(out, 0, sizeof(out));
    CRYPTO_cfb128_8_encrypt(in, out, 20, &key, iv, (int *)&num, 1, rt_block);
    rt_hex("mode.cfb8.enc.ct", out, 20);
    rt_hex("mode.cfb8.enc.iv", iv, 16);
    rt_fill(iv, 16, 5);
    num = 0;
    memset(out, 0, sizeof(out));
    CRYPTO_cfb128_8_encrypt(in, out, 20, &key, iv, (int *)&num, 0, rt_block);
    rt_hex("mode.cfb8.dec.ct", out, 20);
    rt_hex("mode.cfb8.dec.iv", iv, 16);

    /* ---- CFB-1: `length` is a BIT count. One bit leaves the other seven bits of the
     *      destination byte as they were; eight bits process exactly one byte. ---- */
    rt_fill(iv, 16, 6);
    num = 0;
    memset(out, 0x55, sizeof(out));
    CRYPTO_cfb128_1_encrypt(in, out, 1, &key, iv, (int *)&num, 1, rt_block);
    rt_hex("mode.cfb1.one_bit.ct", out, 1);
    rt_hex("mode.cfb1.one_bit.iv", iv, 16);

    rt_fill(iv, 16, 6);
    num = 0;
    memset(out, 0, sizeof(out));
    CRYPTO_cfb128_1_encrypt(in, out, 8, &key, iv, (int *)&num, 1, rt_block);
    rt_hex("mode.cfb1.eight_bits.ct", out, 1);

    rt_fill(iv, 16, 6);
    num = 0;
    memset(out, 0, sizeof(out));
    CRYPTO_cfb128_1_encrypt(in, out, 24, &key, iv, (int *)&num, 0, rt_block);
    rt_hex("mode.cfb1.dec.ct", out, 3);

    /* ---- CTR: the general counter, exact blocks and a partial tail. ---- */
    rt_fill(iv, 16, 7);
    num = 0;
    memset(ecount, 0, sizeof(ecount));
    memset(out, 0, sizeof(out));
    CRYPTO_ctr128_encrypt(in, out, 16, &key, iv, ecount, &num, rt_block);
    rt_hex("mode.ctr.oneblock.ct", out, 16);
    rt_hex("mode.ctr.oneblock.iv", iv, 16);
    printf("mode.ctr.oneblock.num=%u\n", num);

    rt_fill(iv, 16, 7);
    num = 0;
    memset(ecount, 0, sizeof(ecount));
    memset(out, 0, sizeof(out));
    CRYPTO_ctr128_encrypt(in, out, 35, &key, iv, ecount, &num, rt_block);
    rt_hex("mode.ctr.partial.ct", out, 35);
    rt_hex("mode.ctr.partial.iv", iv, 16);
    rt_hex("mode.ctr.partial.ecount", ecount, 16);
    printf("mode.ctr.partial.num=%u\n", num);

    /* A resumed counter: `num = 4` continues a keystream the caller still holds. */
    rt_fill(iv, 16, 7);
    num = 4;
    rt_fill(ecount, 16, 11);
    memset(out, 0, sizeof(out));
    CRYPTO_ctr128_encrypt(in, out, 20, &key, iv, ecount, &num, rt_block);
    rt_hex("mode.ctr.resume.ct", out, 20);
    rt_hex("mode.ctr.resume.ecount", ecount, 16);
    printf("mode.ctr.resume.num=%u\n", num);

    /* ---- CTR with the 32-bit counter routine. ---- */
    rt_fill(iv, 16, 8);
    num = 0;
    memset(ecount, 0, sizeof(ecount));
    memset(out, 0, sizeof(out));
    CRYPTO_ctr128_encrypt_ctr32(in, out, 35, &key, iv, ecount, &num, rt_ctr32);
    rt_hex("mode.ctr32.ct", out, 35);
    rt_hex("mode.ctr32.iv", iv, 16);
    rt_hex("mode.ctr32.ecount", ecount, 16);
    printf("mode.ctr32.num=%u\n", num);

    /* ---- The CTS families, block and cbc spellings, both directions. ---- */
    rt_fill(iv, 16, 12);
    memset(out, 0, sizeof(out));
    {
        size_t ret = CRYPTO_cts128_encrypt_block(in, out, 30, &key, iv, rt_block);

        printf("mode.cts.block.enc.ret=%u\n", (unsigned)ret);
        rt_hex("mode.cts.block.enc.ct", out, 48);
        rt_hex("mode.cts.block.enc.iv", iv, 16);
    }

    rt_fill(iv, 16, 12);
    memset(out, 0, sizeof(out));
    {
        size_t ret = CRYPTO_nistcts128_encrypt_block(in, out, 30, &key, iv, rt_block);

        printf("mode.nistcts.block.enc.ret=%u\n", (unsigned)ret);
        rt_hex("mode.nistcts.block.enc.ct", out, 48);
        rt_hex("mode.nistcts.block.enc.iv", iv, 16);
    }

    rt_fill(iv, 16, 12);
    memset(out, 0, sizeof(out));
    {
        size_t ret = CRYPTO_cts128_encrypt(in, out, 30, &key, iv, rt_cbc);

        printf("mode.cts.cbc.enc.ret=%u\n", (unsigned)ret);
        rt_hex("mode.cts.cbc.enc.ct", out, 32);
        rt_hex("mode.cts.cbc.enc.iv", iv, 16);
    }

    rt_fill(iv, 16, 12);
    memset(out, 0, sizeof(out));
    {
        size_t ret = CRYPTO_nistcts128_encrypt(in, out, 30, &key, iv, rt_cbc);

        printf("mode.nistcts.cbc.enc.ret=%u\n", (unsigned)ret);
        rt_hex("mode.nistcts.cbc.enc.ct", out, 48);
        rt_hex("mode.nistcts.cbc.enc.iv", iv, 16);
    }

    /* Decryption of what was just written, using the same transform. */
    {
        unsigned char cipher[64];
        unsigned char plain[64];
        unsigned char dec_iv[16];

        rt_fill(iv, 16, 12);
        rt_fill(cipher, sizeof(cipher), 0);
        memcpy(plain, cipher, sizeof(cipher));
        memcpy(dec_iv, iv, 16);
        {
            size_t ret = CRYPTO_cts128_decrypt_block(cipher, plain, 30, &key, dec_iv, rt_block);

            printf("mode.cts.block.dec.ret=%u\n", (unsigned)ret);
            rt_hex("mode.cts.block.dec.pt", plain, 32);
        }
        memcpy(dec_iv, iv, 16);
        {
            size_t ret = CRYPTO_nistcts128_decrypt_block(cipher, plain, 30, &key, dec_iv, rt_block);

            printf("mode.nistcts.block.dec.ret=%u\n", (unsigned)ret);
            rt_hex("mode.nistcts.block.dec.pt", plain, 32);
        }
        memcpy(dec_iv, iv, 16);
        {
            size_t ret = CRYPTO_cts128_decrypt(cipher, plain, 30, &key, dec_iv, rt_cbc);

            printf("mode.cts.cbc.dec.ret=%u\n", (unsigned)ret);
            rt_hex("mode.cts.cbc.dec.pt", plain, 32);
        }
        memcpy(dec_iv, iv, 16);
        {
            size_t ret = CRYPTO_nistcts128_decrypt(cipher, plain, 30, &key, dec_iv, rt_cbc);

            printf("mode.nistcts.cbc.dec.ret=%u\n", (unsigned)ret);
            rt_hex("mode.nistcts.cbc.dec.pt", plain, 32);
        }
    }

    /* The short-input arms: a length that cannot be stolen from returns zero and writes
     * nothing. */
    memset(out, 0xcc, sizeof(out));
    printf("mode.cts.block.short_ret=%u\n", (unsigned)CRYPTO_cts128_encrypt_block(in, out, 16, &key, iv, rt_block));
    printf("mode.nistcts.block.short_ret=%u\n", (unsigned)CRYPTO_nistcts128_encrypt_block(in, out, 15, &key, iv, rt_block));
    printf("mode.cts.cbc.short_ret=%u\n", (unsigned)CRYPTO_cts128_encrypt(in, out, 16, &key, iv, rt_cbc));
    printf("mode.nistcts.cbc.short_ret=%u\n", (unsigned)CRYPTO_nistcts128_encrypt(in, out, 15, &key, iv, rt_cbc));
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    rt_modes_blocks();
    rt_aes();
    return 0;
}
