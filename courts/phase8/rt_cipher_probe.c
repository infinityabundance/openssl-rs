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
#include <openssl/des.h>
#include <openssl/modes.h>
#include <openssl/rc2.h>
#include <openssl/rc4.h>

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

static void rt_rc4(void)
{
    RC4_KEY k;
    unsigned char key[16];
    unsigned char in[64];
    unsigned char out[64];
    unsigned char out2[64];

    rt_fill(key, sizeof(key), 1);
    rt_fill(in, sizeof(in), 2);

    printf("rc4.sizeof_key=%u\n", (unsigned)sizeof(RC4_KEY));
    /*
     * `RC4_options` is deliberately NOT printed: its answer is selected at run time from two
     * `OPENSSL_ia32cap` bits (`crypto/rc4/asm/rc4-x86_64.pl`'s `RC4_options`), so the
     * authority's string is a property of the CPU and not of the implementation. The candidate
     * has no CPU dispatch yet -- that is Phase 19's (`docs/RELEASE_GATES.md`) -- so it answers
     * the default arm, and comparing the two would report a host difference as a residual.
     * The authority's value on this host was measured when the string was chosen; see D213.
     */
    printf("rc4.options.skipped=1\n");

    /* The key schedule is a byte permutation, so it is observed as bytes -- and the two
     * indices after a run are part of the state a resumed call depends on. */
    memset(&k, 0, sizeof(k));
    RC4_set_key(&k, 16, key);
    printf("rc4.set_key.x=%u\n", (unsigned)k.x);
    printf("rc4.set_key.y=%u\n", (unsigned)k.y);
    rt_hex("rc4.set_key.data", (const unsigned char *)k.data, 64);

    memset(out, 0, sizeof(out));
    RC4(&k, 32, in, out);
    rt_hex("rc4.ct", out, 32);
    printf("rc4.state.x=%u\n", (unsigned)k.x);
    printf("rc4.state.y=%u\n", (unsigned)k.y);

    /* A second call resumes the keystream from the retained state, which is the observable a
     * transcription that re-initialises would get wrong. */
    memset(out2, 0, sizeof(out2));
    RC4(&k, 32, in + 32, out2);
    rt_hex("rc4.ct2", out2, 32);
    printf("rc4.state2.x=%u\n", (unsigned)k.x);
    printf("rc4.state2.y=%u\n", (unsigned)k.y);

    /* The classic `Key`/`Plaintext` vector. */
    memset(&k, 0, sizeof(k));
    RC4_set_key(&k, 3, (const unsigned char *)"Key");
    memset(out, 0, sizeof(out));
    RC4(&k, 9, (const unsigned char *)"Plaintext", out);
    rt_hex("rc4.classic", out, 9);

    /* Different key lengths exercise the wrap in the KSA. */
    memset(&k, 0, sizeof(k));
    RC4_set_key(&k, 1, (const unsigned char *)"a");
    memset(out, 0, sizeof(out));
    RC4(&k, 16, in, out);
    rt_hex("rc4.keylen1", out, 16);

    memset(&k, 0, sizeof(k));
    RC4_set_key(&k, 32, key);
    memset(out, 0, sizeof(out));
    RC4(&k, 0, in, out);
    rt_hex("rc4.zero_len", out, 4);
    printf("rc4.zero_len.state.x=%u\n", (unsigned)k.x);
}

static void rt_des(void)
{
    unsigned char key[24];
    unsigned char in[48];
    unsigned char out[64];
    unsigned char iv[8];
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock ck;
    int num;

    printf("des.sizeof_schedule=%u\n", (unsigned)sizeof(DES_key_schedule));
    /*
     * `DES_options` is host-independent here: the portable arm is compiled because this
     * profile's asm_arch has no `des-586` object, and it answers the constant
     * `des(int)` (`crypto/des/ecb_enc.c:20-33`).
     */
    printf("des.options=%s\n", DES_options());

    rt_fill(key, 8, 1);
    /* Build a parity-correct key so `DES_set_key` can answer 0 rather than -1. */
    memcpy(ck, key, 8);
    DES_set_odd_parity(&ck);
    printf("des.check_parity=%d\n", DES_check_key_parity(&ck));
    printf("des.set_key=%d\n", DES_set_key(&ck, &ks1));
    printf("des.key_sched=%d\n", DES_key_sched(&ck, &ks1));
    printf("des.set_key_checked=%d\n", DES_set_key_checked(&ck, &ks1));
    /* The whole 128-byte schedule is the strongest observation: a wrong PC1, shift or S-box
     * changes it, and a wrong round-order transcription changes it too. */
    rt_hex("des.ks1", (const unsigned char *)&ks1, sizeof(ks1));

    /* Weak and semi-weak keys, and a wrong-parity key. */
    {
        DES_cblock w1 = { 1, 1, 1, 1, 1, 1, 1, 1 };
        DES_cblock w2 = { 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE };
        DES_cblock s1 = { 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE };
        DES_cblock silly = { 0, 0, 0, 0, 0, 0, 0, 0 };
        DES_key_schedule wk;

        printf("des.weak.0101=%d\n", DES_is_weak_key(&w1));
        printf("des.weak.fefe=%d\n", DES_is_weak_key(&w2));
        printf("des.weak.semi=%d\n", DES_is_weak_key(&s1));
        printf("des.set_key.weak=%d\n", DES_set_key(&w1, &wk));
        printf("des.set_key.wrongparity=%d\n", DES_set_key(&silly, &wk));
        printf("des.check_parity.zero=%d\n", DES_check_key_parity(&silly));
    }

    /* `DES_encrypt1`/`DES_encrypt2`, and the 3DES entry points. */
    {
        DES_LONG d1[2], d2[2];

        d1[0] = 0x01234567u;
        d1[1] = 0x89abcdefu;
        d2[0] = d1[0];
        d2[1] = d1[1];
        DES_encrypt1(d1, &ks1, DES_ENCRYPT);
        rt_hex("des.encrypt1.enc", (const unsigned char *)d1, 8);
        DES_encrypt1(d1, &ks1, DES_DECRYPT);
        rt_hex("des.encrypt1.dec", (const unsigned char *)d1, 8);
        DES_encrypt2(d2, &ks1, DES_ENCRYPT);
        rt_hex("des.encrypt2.enc", (const unsigned char *)d2, 8);
    }

    rt_fill(key, 24, 2);
    memcpy(ck, key, 8);
    DES_set_odd_parity(&ck);
    DES_set_key_unchecked(&ck, &ks1);
    memcpy(ck, key + 8, 8);
    DES_set_odd_parity(&ck);
    DES_set_key_unchecked(&ck, &ks2);
    memcpy(ck, key + 16, 8);
    DES_set_odd_parity(&ck);
    DES_set_key_unchecked(&ck, &ks3);

    rt_fill(in, sizeof(in), 3);
    memset(out, 0, sizeof(out));
    rt_fill(iv, 8, 4);
    DES_ecb3_encrypt((const_DES_cblock *)in, (DES_cblock *)out, &ks1, &ks2, &ks3, DES_ENCRYPT);
    rt_hex("des.ecb3.enc", out, 8);
    DES_ecb3_encrypt((const_DES_cblock *)out, (DES_cblock *)out + 8, &ks1, &ks2, &ks3, DES_DECRYPT);
    rt_hex("des.ecb3.dec", out + 8, 8);

    {
        DES_LONG e3[2];

        e3[0] = 0x11223344u;
        e3[1] = 0x55667788u;
        DES_encrypt3(e3, &ks1, &ks2, &ks3);
        rt_hex("des.encrypt3", (const unsigned char *)e3, 8);
        DES_decrypt3(e3, &ks1, &ks2, &ks3);
        rt_hex("des.decrypt3", (const unsigned char *)e3, 8);
    }

    /* ECB through the public entry point. */
    memset(out, 0, sizeof(out));
    rt_fill(iv, 8, 4);
    DES_ecb_encrypt((const_DES_cblock *)in, (DES_cblock *)out, &ks1, DES_ENCRYPT);
    rt_hex("des.ecb.enc", out, 8);
    DES_ecb_encrypt((const_DES_cblock *)out, (DES_cblock *)out + 8, &ks1, DES_DECRYPT);
    rt_hex("des.ecb.dec", out + 8, 8);

    /* `DES_cbc_encrypt` does NOT update the IV; `DES_ncbc_encrypt` does. */
    rt_fill(iv, 8, 5);
    memset(out, 0, sizeof(out));
    DES_cbc_encrypt(in, out, 24, &ks1, &iv, DES_ENCRYPT);
    rt_hex("des.cbc.enc.ct", out, 24);
    rt_hex("des.cbc.enc.iv", iv, 8);

    rt_fill(iv, 8, 5);
    memset(out, 0, sizeof(out));
    DES_ncbc_encrypt(in, out, 24, &ks1, &iv, DES_ENCRYPT);
    rt_hex("des.ncbc.enc.ct", out, 24);
    rt_hex("des.ncbc.enc.iv", iv, 8);

    rt_fill(iv, 8, 5);
    memset(out, 0, sizeof(out));
    DES_ncbc_encrypt(in, out, 24, &ks1, &iv, DES_DECRYPT);
    rt_hex("des.ncbc.dec", out, 24);
    rt_hex("des.ncbc.dec.iv", iv, 8);

    /* A partial final block, which the `c2ln`/`l2cn` arms take. */
    rt_fill(iv, 8, 6);
    memset(out, 0, sizeof(out));
    DES_ncbc_encrypt(in, out, 20, &ks1, &iv, DES_ENCRYPT);
    rt_hex("des.ncbc.partial", out, 24);

    /* EDE3-CBC. */
    rt_fill(iv, 8, 7);
    memset(out, 0, sizeof(out));
    DES_ede3_cbc_encrypt(in, out, 24, &ks1, &ks2, &ks3, &iv, DES_ENCRYPT);
    rt_hex("des.ede3cbc.enc", out, 24);
    rt_hex("des.ede3cbc.enc.iv", iv, 8);
    DES_ede3_cbc_encrypt(out, out + 24, 24, &ks1, &ks2, &ks3, &iv, DES_DECRYPT);
    rt_hex("des.ede3cbc.dec", out + 24, 24);

    /* PCBC and XCBC. */
    rt_fill(iv, 8, 8);
    memset(out, 0, sizeof(out));
    DES_pcbc_encrypt(in, out, 24, &ks1, &iv, DES_ENCRYPT);
    rt_hex("des.pcbc.enc", out, 24);
    DES_pcbc_encrypt(out, out + 24, 24, &ks1, &iv, DES_DECRYPT);
    rt_hex("des.pcbc.dec", out + 24, 24);

    rt_fill(iv, 8, 9);
    memset(out, 0, sizeof(out));
    DES_xcbc_encrypt(in, out, 24, &ks1, &iv, (const_DES_cblock *)(key + 8),
                     (const_DES_cblock *)(key + 16), DES_ENCRYPT);
    rt_hex("des.xcbc.enc", out, 24);
    rt_hex("des.xcbc.enc.iv", iv, 8);
    DES_xcbc_encrypt(out, out + 24, 24, &ks1, &iv, (const_DES_cblock *)(key + 8),
                     (const_DES_cblock *)(key + 16), DES_DECRYPT);
    rt_hex("des.xcbc.dec", out + 24, 24);

    /* CFB-64 with a resumed `num`, and the EDE3 spelling. */
    rt_fill(iv, 8, 10);
    num = 3;
    memset(out, 0, sizeof(out));
    DES_cfb64_encrypt(in, out, 24, &ks1, &iv, &num, DES_ENCRYPT);
    rt_hex("des.cfb64.enc", out, 24);
    rt_hex("des.cfb64.enc.iv", iv, 8);
    printf("des.cfb64.enc.num=%d\n", num);

    rt_fill(iv, 8, 10);
    num = 3;
    memset(out, 0, sizeof(out));
    DES_cfb64_encrypt(in, out, 24, &ks1, &iv, &num, DES_DECRYPT);
    rt_hex("des.cfb64.dec", out, 24);
    printf("des.cfb64.dec.num=%d\n", num);

    rt_fill(iv, 8, 11);
    num = 0;
    memset(out, 0, sizeof(out));
    DES_ede3_cfb64_encrypt(in, out, 24, &ks1, &ks2, &ks3, &iv, &num, DES_ENCRYPT);
    rt_hex("des.ede3cfb64.enc", out, 24);

    /* OFB-64 with `num`, and the EDE3 spelling. */
    rt_fill(iv, 8, 12);
    num = 5;
    memset(out, 0, sizeof(out));
    DES_ofb64_encrypt(in, out, 24, &ks1, &iv, &num);
    rt_hex("des.ofb64.enc", out, 24);
    rt_hex("des.ofb64.enc.iv", iv, 8);
    printf("des.ofb64.enc.num=%d\n", num);

    rt_fill(iv, 8, 12);
    num = 5;
    memset(out, 0, sizeof(out));
    DES_ede3_ofb64_encrypt(in, out, 24, &ks1, &ks2, &ks3, &iv, &num);
    rt_hex("des.ede3ofb64.enc", out, 24);

    /* The bit-oriented CFB-r and OFB-r spellings. */
    rt_fill(iv, 8, 13);
    memset(out, 0, sizeof(out));
    DES_cfb_encrypt(in, out, 12, 12, &ks1, &iv, DES_ENCRYPT);
    rt_hex("des.cfb12.enc", out, 12);
    rt_hex("des.cfb12.enc.iv", iv, 8);

    rt_fill(iv, 8, 13);
    memset(out, 0, sizeof(out));
    DES_cfb_encrypt(in, out, 12, 12, &ks1, &iv, DES_DECRYPT);
    rt_hex("des.cfb12.dec", out, 12);

    rt_fill(iv, 8, 14);
    memset(out, 0, sizeof(out));
    DES_ofb_encrypt(in, out, 12, 12, &ks1, &iv);
    rt_hex("des.ofb12.enc", out, 12);
    rt_hex("des.ofb12.enc.iv", iv, 8);

    rt_fill(iv, 8, 15);
    memset(out, 0, sizeof(out));
    DES_ede3_cfb_encrypt(in, out, 12, 12, &ks1, &ks2, &ks3, &iv, DES_ENCRYPT);
    rt_hex("des.ede3cfb12.enc", out, 12);

    /* CBC checksum: the returned word and the optional output block. */
    {
        DES_cblock cksum;
        DES_LONG r;

        rt_fill(iv, 8, 16);
        memset(&cksum, 0, sizeof(cksum));
        r = DES_cbc_cksum(in, &cksum, 20, &ks1, &iv);
        printf("des.cbc_cksum.ret=%08x\n", (unsigned)r);
        rt_hex("des.cbc_cksum.out", (const unsigned char *)&cksum, 8);
    }

    /* QUAD checksum, with its four-output-count loop. */
    {
        DES_cblock outb[4];
        DES_cblock seed;
        DES_LONG r;

        rt_fill(seed, 8, 17);
        memset(outb, 0, sizeof(outb));
        r = DES_quad_cksum(in, outb, 12, 4, &seed);
        printf("des.quad_cksum.ret=%08x\n", (unsigned)r);
        rt_hex("des.quad_cksum.out", (const unsigned char *)outb, 32);
    }

    /* The string-key helpers. */
    {
        DES_cblock k1, k2;

        DES_string_to_key("The quick brown fox", &k1);
        rt_hex("des.string_to_key", (const unsigned char *)&k1, 8);
        DES_string_to_2keys("abcdefghijklmnopq", &k1, &k2);
        rt_hex("des.string_to_2keys.k1", (const unsigned char *)&k1, 8);
        rt_hex("des.string_to_2keys.k2", (const unsigned char *)&k2, 8);
    }

    /* The crypt(3) spelling, whose `fcrypt_body` is a distinct 25-iteration loop. */
    {
        char ret[14];

        memset(ret, 0, sizeof(ret));
        printf("des.fcrypt.null=%d\n", DES_fcrypt("password", "\0x", ret) == NULL);
        memset(ret, 0, sizeof(ret));
        printf("des.fcrypt.ret=%d\n", DES_fcrypt("password", "ab", ret) != NULL);
        printf("des.fcrypt=%s\n", ret);
        printf("des.crypt=%s\n", DES_crypt("password", "ab"));
    }

    /* A second key schedule, so the diff sees two distinct 128-byte schedules. */
    rt_fill(key, 8, 18);
    memcpy(ck, key, 8);
    DES_set_odd_parity(&ck);
    DES_set_key_unchecked(&ck, &ks2);
    rt_hex("des.ks2", (const unsigned char *)&ks2, sizeof(ks2));
}

static void rt_rc2(void)
{
    RC2_KEY k;
    unsigned char key[16];
    unsigned char in[32];
    unsigned char out[64];
    unsigned char iv[8];
    unsigned long d[2];
    int num;

    rt_fill(key, sizeof(key), 1);
    rt_fill(in, sizeof(in), 2);
    printf("rc2.sizeof_key=%u\n", (unsigned)sizeof(RC2_KEY));

    memset(&k, 0, sizeof(k));
    RC2_set_key(&k, 16, key, 128);
    rt_hex("rc2.ks", (const unsigned char *)&k, sizeof(k));

    d[0] = 0x01234567UL;
    d[1] = 0x89abcdefUL;
    RC2_encrypt(d, &k);
    rt_hex("rc2.encrypt", (const unsigned char *)d, 8);
    RC2_decrypt(d, &k);
    rt_hex("rc2.decrypt", (const unsigned char *)d, 8);

    memset(out, 0, sizeof(out));
    RC2_ecb_encrypt(in, out, &k, RC2_ENCRYPT);
    rt_hex("rc2.ecb.enc", out, 8);
    RC2_ecb_encrypt(out, out + 8, &k, RC2_DECRYPT);
    rt_hex("rc2.ecb.dec", out + 8, 8);

    rt_fill(iv, 8, 3);
    memset(out, 0, sizeof(out));
    RC2_cbc_encrypt(in, out, 24, &k, iv, RC2_ENCRYPT);
    rt_hex("rc2.cbc.enc", out, 24);
    rt_hex("rc2.cbc.enc.iv", iv, 8);
    RC2_cbc_encrypt(out, out + 24, 24, &k, iv, RC2_DECRYPT);
    rt_hex("rc2.cbc.dec", out + 24, 24);

    rt_fill(iv, 8, 4);
    num = 3;
    memset(out, 0, sizeof(out));
    RC2_cfb64_encrypt(in, out, 24, &k, iv, &num, RC2_ENCRYPT);
    rt_hex("rc2.cfb64.enc", out, 24);
    printf("rc2.cfb64.num=%d\n", num);
    rt_fill(iv, 8, 5);
    num = 0;
    memset(out, 0, sizeof(out));
    RC2_ofb64_encrypt(in, out, 24, &k, iv, &num);
    rt_hex("rc2.ofb64.enc", out, 24);
    rt_hex("rc2.ofb64.enc.iv", iv, 8);
    printf("rc2.ofb64.num=%d\n", num);

    /* The corpus's own first vector, so the recipe value is seen on both sides. */
    {
        unsigned char zkey[16] = { 0 };
        unsigned char pt[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
        unsigned char ct[8];
        RC2_KEY zk;

        memset(&zk, 0, sizeof(zk));
        RC2_set_key(&zk, 16, zkey, 128);
        rt_hex("rc2.zero.ks", (const unsigned char *)&zk, sizeof(zk));
        memset(ct, 0, sizeof(ct));
        RC2_ecb_encrypt(pt, ct, &zk, RC2_ENCRYPT);
        rt_hex("rc2.zero.ecb", ct, 8);
    }

    /* The BSAFE-style effective-key-bits reduction is an observable: 40 and 64 bits, and the
     * default 128, build three different schedules from the same key. */
    {
        RC2_KEY k40, k64;

        memset(&k40, 0, sizeof(k40));
        RC2_set_key(&k40, 16, key, 40);
        rt_hex("rc2.ks40", (const unsigned char *)&k40, sizeof(k40));
        memset(&k64, 0, sizeof(k64));
        RC2_set_key(&k64, 16, key, 64);
        rt_hex("rc2.ks64", (const unsigned char *)&k64, sizeof(k64));
        memset(out, 0, sizeof(out));
        RC2_ecb_encrypt(in, out, &k40, RC2_ENCRYPT);
        rt_hex("rc2.ecb40.enc", out, 8);
        memset(out, 0, sizeof(out));
        RC2_ecb_encrypt(in, out, &k64, RC2_ENCRYPT);
        rt_hex("rc2.ecb64.enc", out, 8);
    }
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
    rt_rc4();
    rt_des();
    rt_rc2();
    return 0;
}
