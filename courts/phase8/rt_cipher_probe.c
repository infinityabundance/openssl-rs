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
#include <openssl/blowfish.h>
#include <openssl/camellia.h>
#include <openssl/cast.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/idea.h>
#include <openssl/modes.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rc2.h>
#include <openssl/rc4.h>
#include <openssl/seed.h>

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
     * `RC4_options`'s *value* is deliberately not compared: its answer is selected at run time
     * from two `OPENSSL_ia32cap` bits (`crypto/rc4/asm/rc4-x86_64.pl`'s `RC4_options`), so the
     * authority's string is a property of the CPU and not of the implementation. The candidate
     * has no CPU dispatch yet -- that is Phase 19's (`docs/RELEASE_GATES.md`) -- so it answers
     * the default arm, and comparing the two would report a host difference as a residual
     * (docs/DECISIONS.md D213).
     *
     * The symbol is nevertheless courted, because a host-selected *value* is not a reason to
     * leave an export without any edge: the probe calls it and records the facts about its
     * answer that are the same on every host -- that it is non-NULL, that it has the one shape
     * the perlasm can produce, and that it is one of the three spellings that file can return.
     * Which of the three is what the host decides, and that choice is declined rather than
     * forgotten.
     */
    {
        const char *o = RC4_options();
        size_t n = o == NULL ? 0u : strlen(o);

        printf("rc4.options.present=%d\n", o != NULL);
        printf("rc4.options.shape=%d\n",
               o != NULL && n >= 6u && strncmp(o, "rc4(", 4) == 0 && o[n - 1] == ')');
        printf("rc4.options.known_spelling=%d\n",
               o != NULL
                   && (strcmp(o, "rc4(16x,int)") == 0 || strcmp(o, "rc4(8x,int)") == 0
                       || strcmp(o, "rc4(8x,char)") == 0));
        printf("rc4.options.value_compared=0\n");
    }

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

static void rt_bf(void)
{
    BF_KEY k;
    unsigned char key[16];
    unsigned char in[24];
    unsigned char out[48];
    unsigned char iv[8];
    int num;

    rt_fill(key, sizeof(key), 1);
    rt_fill(in, sizeof(in), 2);
    printf("bf.sizeof_key=%u\n", (unsigned)sizeof(BF_KEY));
    printf("bf.options=%s\n", BF_options());

    memset(&k, 0, sizeof(k));
    BF_set_key(&k, 16, key);
    rt_hex("bf.ks", (const unsigned char *)&k, sizeof(k));

    memset(out, 0, sizeof(out));
    BF_ecb_encrypt(in, out, &k, BF_ENCRYPT);
    rt_hex("bf.ecb.enc", out, 8);
    BF_ecb_encrypt(out, out + 8, &k, BF_DECRYPT);
    rt_hex("bf.ecb.dec", out + 8, 8);

    /* The corpus's own first BF-ECB block, so both sides see the recipe value. */
    {
        static const unsigned char rkey[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        static const unsigned char rpt[16] = { 0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                                               0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
        BF_KEY rk;

        memset(&rk, 0, sizeof(rk));
        BF_set_key(&rk, 16, rkey);
        memset(out, 0, sizeof(out));
        BF_ecb_encrypt(rpt, out, &rk, BF_ENCRYPT);
        BF_ecb_encrypt(rpt + 8, out + 8, &rk, BF_ENCRYPT);
        rt_hex("bf.recipe.ecb", out, 16);
    }

    rt_fill(iv, 8, 3);
    memset(out, 0, sizeof(out));
    BF_cbc_encrypt(in, out, 24, &k, iv, BF_ENCRYPT);
    rt_hex("bf.cbc.enc", out, 24);
    rt_hex("bf.cbc.enc.iv", iv, 8);
    BF_cbc_encrypt(out, out + 24, 24, &k, iv, BF_DECRYPT);
    rt_hex("bf.cbc.dec", out + 24, 24);

    rt_fill(iv, 8, 4);
    num = 3;
    memset(out, 0, sizeof(out));
    BF_cfb64_encrypt(in, out, 24, &k, iv, &num, BF_ENCRYPT);
    rt_hex("bf.cfb64.enc", out, 24);
    printf("bf.cfb64.num=%d\n", num);

    rt_fill(iv, 8, 5);
    num = 0;
    memset(out, 0, sizeof(out));
    BF_ofb64_encrypt(in, out, 24, &k, iv, &num);
    rt_hex("bf.ofb64.enc", out, 24);
    rt_hex("bf.ofb64.enc.iv", iv, 8);

    /* BF_encrypt/BF_decrypt directly, on a DES_LONG pair. */
    {
        unsigned int d[2] = { 0x01234567u, 0x89abcdefu };

        BF_encrypt(d, &k);
        rt_hex("bf.encrypt", (const unsigned char *)d, 8);
        BF_decrypt(d, &k);
        rt_hex("bf.decrypt", (const unsigned char *)d, 8);
    }
}

static void rt_cast5(void)
{
    CAST_KEY k, shortk;
    unsigned char key[16];
    unsigned char in[24];
    unsigned char out[48];
    unsigned char iv[8];
    int num;

    rt_fill(key, sizeof(key), 1);
    rt_fill(in, sizeof(in), 2);
    printf("cast.sizeof_key=%u\n", (unsigned)sizeof(CAST_KEY));

    memset(&k, 0, sizeof(k));
    CAST_set_key(&k, 16, key);
    rt_hex("cast.ks16", (const unsigned char *)&k, sizeof(k));

    memset(out, 0, sizeof(out));
    CAST_ecb_encrypt(in, out, &k, CAST_ENCRYPT);
    rt_hex("cast.ecb.enc", out, 8);
    CAST_ecb_encrypt(out, out + 8, &k, CAST_DECRYPT);
    rt_hex("cast.ecb.dec", out + 8, 8);

    /* RFC 2144's CAST5-ECB vector, from the corpus. */
    {
        static const unsigned char rkey[16] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
                                                0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9a };
        static const unsigned char rpt[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
        CAST_KEY rk;

        memset(&rk, 0, sizeof(rk));
        CAST_set_key(&rk, 16, rkey);
        memset(out, 0, sizeof(out));
        CAST_ecb_encrypt(rpt, out, &rk, CAST_ENCRYPT);
        rt_hex("cast.recipe.ecb", out, 8);
    }

    /* An eight-byte key sets `short_key`, which removes four rounds; the flag is at the tail of
     * the 132-byte CAST_KEY and the schedule differs too. */
    memset(&shortk, 0, sizeof(shortk));
    CAST_set_key(&shortk, 8, key);
    rt_hex("cast.ks8", (const unsigned char *)&shortk, sizeof(shortk));
    memset(out, 0, sizeof(out));
    CAST_ecb_encrypt(in, out, &shortk, CAST_ENCRYPT);
    rt_hex("cast.ecb8.enc", out, 8);

    rt_fill(iv, 8, 3);
    memset(out, 0, sizeof(out));
    CAST_cbc_encrypt(in, out, 24, &k, iv, CAST_ENCRYPT);
    rt_hex("cast.cbc.enc", out, 24);
    rt_hex("cast.cbc.enc.iv", iv, 8);
    CAST_cbc_encrypt(out, out + 24, 24, &k, iv, CAST_DECRYPT);
    rt_hex("cast.cbc.dec", out + 24, 24);

    rt_fill(iv, 8, 4);
    num = 3;
    memset(out, 0, sizeof(out));
    CAST_cfb64_encrypt(in, out, 24, &k, iv, &num, CAST_ENCRYPT);
    rt_hex("cast.cfb64.enc", out, 24);
    printf("cast.cfb64.num=%d\n", num);

    rt_fill(iv, 8, 5);
    num = 0;
    memset(out, 0, sizeof(out));
    CAST_ofb64_encrypt(in, out, 24, &k, iv, &num);
    rt_hex("cast.ofb64.enc", out, 24);
    rt_hex("cast.ofb64.enc.iv", iv, 8);

    /* CAST_encrypt/BF-like direct call on a word pair. */
    {
        unsigned int w[2] = { 0x01234567u, 0x89abcdefu };

        CAST_encrypt(w, &k);
        rt_hex("cast.encrypt", (const unsigned char *)w, 8);
        CAST_decrypt(w, &k);
        rt_hex("cast.decrypt", (const unsigned char *)w, 8);
    }
}

static void rt_idea(void)
{
    IDEA_KEY_SCHEDULE ek, dk;
    unsigned char key[16];
    unsigned char in[24];
    unsigned char out[48];
    unsigned char iv[8];
    int num;

    rt_fill(key, sizeof(key), 1);
    rt_fill(in, sizeof(in), 2);
    printf("idea.sizeof_key=%u\n", (unsigned)sizeof(IDEA_KEY_SCHEDULE));
    printf("idea.options=%s\n", IDEA_options());

    memset(&ek, 0, sizeof(ek));
    IDEA_set_encrypt_key(key, &ek);
    rt_hex("idea.ek", (const unsigned char *)&ek, sizeof(ek));
    memset(&dk, 0, sizeof(dk));
    IDEA_set_decrypt_key(&ek, &dk);
    rt_hex("idea.dk", (const unsigned char *)&dk, sizeof(dk));

    memset(out, 0, sizeof(out));
    IDEA_ecb_encrypt(in, out, &ek);
    rt_hex("idea.ecb.enc", out, 8);
    IDEA_ecb_encrypt(out, out + 8, &dk);
    rt_hex("idea.ecb.dec", out + 8, 8);

    /* The corpus's classic vector. */
    {
        static const unsigned char rkey[16] = { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
                                                0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 };
        static const unsigned char rpt[8] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 };
        IDEA_KEY_SCHEDULE rk;

        memset(&rk, 0, sizeof(rk));
        IDEA_set_encrypt_key(rkey, &rk);
        memset(out, 0, sizeof(out));
        IDEA_ecb_encrypt(rpt, out, &rk);
        rt_hex("idea.recipe.ecb", out, 8);
    }

    rt_fill(iv, 8, 3);
    memset(out, 0, sizeof(out));
    IDEA_cbc_encrypt(in, out, 24, &ek, iv, IDEA_ENCRYPT);
    rt_hex("idea.cbc.enc", out, 24);
    rt_hex("idea.cbc.enc.iv", iv, 8);
    IDEA_cbc_encrypt(out, out + 24, 24, &dk, iv, IDEA_DECRYPT);
    rt_hex("idea.cbc.dec", out + 24, 24);

    rt_fill(iv, 8, 4);
    num = 3;
    memset(out, 0, sizeof(out));
    IDEA_cfb64_encrypt(in, out, 24, &ek, iv, &num, IDEA_ENCRYPT);
    rt_hex("idea.cfb64.enc", out, 24);
    printf("idea.cfb64.num=%d\n", num);

    rt_fill(iv, 8, 5);
    num = 0;
    memset(out, 0, sizeof(out));
    IDEA_ofb64_encrypt(in, out, 24, &ek, iv, &num);
    rt_hex("idea.ofb64.enc", out, 24);
    rt_hex("idea.ofb64.enc.iv", iv, 8);

    /* IDEA's own poison arm: a negative `*num` is preserved and nothing is written. */
    num = -1;
    rt_fill(iv, 8, 6);
    memset(out, 0xcc, sizeof(out));
    IDEA_cfb64_encrypt(in, out, 8, &ek, iv, &num, IDEA_ENCRYPT);
    printf("idea.cfb64.poison_num=%d\n", num);
    rt_hex("idea.cfb64.poison_out", out, 8);

    num = -1;
    memset(out, 0xcc, sizeof(out));
    IDEA_ofb64_encrypt(in, out, 8, &ek, iv, &num);
    printf("idea.ofb64.poison_num=%d\n", num);
    rt_hex("idea.ofb64.poison_out", out, 8);
}

static void rt_seed(void)
{
    SEED_KEY_SCHEDULE ks;
    unsigned char key[16];
    unsigned char in[32];
    unsigned char out[64];
    unsigned char iv[16];
    int num;

    rt_fill(key, sizeof(key), 1);
    rt_fill(in, sizeof(in), 2);
    printf("seed.sizeof_key=%u\n", (unsigned)sizeof(SEED_KEY_SCHEDULE));

    memset(&ks, 0, sizeof(ks));
    SEED_set_key(key, &ks);
    rt_hex("seed.ks", (const unsigned char *)&ks, sizeof(ks));

    memset(out, 0, sizeof(out));
    SEED_ecb_encrypt(in, out, &ks, 1);
    rt_hex("seed.ecb.enc", out, 16);
    SEED_ecb_encrypt(out, out + 16, &ks, 0);
    rt_hex("seed.ecb.dec", out + 16, 16);

    /* The corpus's SEED-ECB vector. */
    {
        static const unsigned char rkey[16] = { 0 };
        static const unsigned char rpt[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        SEED_KEY_SCHEDULE rk;

        memset(&rk, 0, sizeof(rk));
        SEED_set_key(rkey, &rk);
        memset(out, 0, sizeof(out));
        SEED_ecb_encrypt(rpt, out, &rk, 1);
        rt_hex("seed.recipe.ecb", out, 16);
    }

    rt_fill(iv, 16, 3);
    memset(out, 0, sizeof(out));
    SEED_cbc_encrypt(in, out, 32, &ks, iv, 1);
    rt_hex("seed.cbc.enc", out, 32);
    rt_hex("seed.cbc.enc.iv", iv, 16);
    SEED_cbc_encrypt(out, out + 32, 32, &ks, iv, 0);
    rt_hex("seed.cbc.dec", out + 32, 32);

    rt_fill(iv, 16, 4);
    num = 5;
    memset(out, 0, sizeof(out));
    SEED_cfb128_encrypt(in, out, 20, &ks, iv, &num, 1);
    rt_hex("seed.cfb128.enc", out, 20);
    printf("seed.cfb128.num=%d\n", num);

    rt_fill(iv, 16, 5);
    num = 0;
    memset(out, 0, sizeof(out));
    SEED_ofb128_encrypt(in, out, 20, &ks, iv, &num);
    rt_hex("seed.ofb128.enc", out, 20);
    rt_hex("seed.ofb128.enc.iv", iv, 16);
}

static void rt_camellia(void)
{
    CAMELLIA_KEY ck;
    unsigned char key[32];
    unsigned char in[48];
    unsigned char out[64];
    unsigned char iv[16];
    unsigned char ecount[16];
    int num;

    printf("camellia.sizeof_key=%u\n", (unsigned)sizeof(CAMELLIA_KEY));

    /* The three key lengths, each with the recipe's own ECB vector. The schedule's KL/KB/KR
     * limbs mean a wrong rotation or complement shows up in the 272-byte table. */
    {
        static const struct {
            int bits;
            unsigned char key[32];
        } cases[3] = {
            { 128, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 } },
            { 192, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 } },
            { 256, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } },
        };
        static const unsigned char pt[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
        int i;

        for (i = 0; i < 3; i++) {
            memset(&ck, 0, sizeof(ck));
            printf("camellia.set_key.%d=%d\n", cases[i].bits,
                   Camellia_set_key(cases[i].key, cases[i].bits, &ck));
            /*
             * `camellia.ks.*` is deliberately NOT printed. On x86_64 the authority builds
             * the perlasm arm (`crypto/camellia/build.info:6` selects
             * `cmll-x86_64.s cmll_misc.c`, so `camellia.c` is not compiled), and that arm
             * supplies its own `Camellia_Ekeygen` (`crypto/camellia/asm/cmll-x86_64.pl:443`)
             * whose `CAMELLIA_KEY` layout is a different arrangement built for its own round
             * function. The bytes are therefore an arm-specific internal representation, not
             * part of the externally observable contract; comparing the asm authority's table
             * with the portable arm's would report a representation difference as a residual.
             * The schedule is observed through everything it determines instead: the recipe
             * ECB vectors and every mode below. See D222.
             */
            printf("camellia.ks.skipped=%d\n", cases[i].bits);
            printf("camellia.grand_rounds.%d=%d\n", cases[i].bits, ck.grand_rounds);
            memset(out, 0, sizeof(out));
            Camellia_ecb_encrypt(pt, out, &ck, CAMELLIA_ENCRYPT);
            rt_hexf("camellia.recipe.ecb", cases[i].bits, out, 16);
        }
    }

    /* A refused length and a NULL key, both before the table is touched. */
    {
        CAMELLIA_KEY bad;

        memset(&bad, 0, sizeof(bad));
        printf("camellia.set_key.64=%d\n", Camellia_set_key(key, 64, &bad));
        printf("camellia.set_key.nullkey=%d\n", Camellia_set_key(NULL, 128, &bad));
    }

    /* One deterministic key, the block round trip, and every mode. */
    rt_fill(key, 32, 1);
    rt_fill(in, sizeof(in), 2);
    memset(&ck, 0, sizeof(ck));
    Camellia_set_key(key, 128, &ck);
    memset(out, 0, sizeof(out));
    Camellia_ecb_encrypt(in, out, &ck, CAMELLIA_ENCRYPT);
    rt_hex("camellia.ecb.enc", out, 16);
    Camellia_ecb_encrypt(out, out + 16, &ck, CAMELLIA_DECRYPT);
    rt_hex("camellia.ecb.dec", out + 16, 16);

    rt_fill(iv, 16, 3);
    memset(out, 0, sizeof(out));
    Camellia_cbc_encrypt(in, out, 32, &ck, iv, 1);
    rt_hex("camellia.cbc.enc", out, 32);
    rt_hex("camellia.cbc.enc.iv", iv, 16);
    Camellia_cbc_encrypt(out, out + 32, 32, &ck, iv, 0);
    rt_hex("camellia.cbc.dec", out + 32, 32);

    rt_fill(iv, 16, 4);
    num = 5;
    memset(out, 0, sizeof(out));
    Camellia_cfb128_encrypt(in, out, 20, &ck, iv, &num, 1);
    rt_hex("camellia.cfb128.enc", out, 20);
    rt_hex("camellia.cfb128.enc.iv", iv, 16);
    printf("camellia.cfb128.num=%d\n", num);

    rt_fill(iv, 16, 5);
    num = 0;
    memset(out, 0, sizeof(out));
    Camellia_cfb8_encrypt(in, out, 20, &ck, iv, &num, 1);
    rt_hex("camellia.cfb8.enc", out, 20);
    rt_hex("camellia.cfb8.enc.iv", iv, 16);

    /* CFB-1's `length` is a bit count and the input is packed MS bit first. */
    rt_fill(iv, 16, 6);
    num = 0;
    memset(out, 0x55, sizeof(out));
    Camellia_cfb1_encrypt(in, out, 1, &ck, iv, &num, 1);
    rt_hex("camellia.cfb1.one_bit", out, 1);
    rt_fill(iv, 16, 6);
    num = 0;
    memset(out, 0, sizeof(out));
    Camellia_cfb1_encrypt(in, out, 8, &ck, iv, &num, 1);
    rt_hex("camellia.cfb1.eight_bits", out, 1);
    rt_fill(iv, 16, 6);
    num = 0;
    memset(out, 0, sizeof(out));
    Camellia_cfb1_encrypt(in, out, 24, &ck, iv, &num, 0);
    rt_hex("camellia.cfb1.dec", out, 3);

    rt_fill(iv, 16, 7);
    num = 0;
    memset(out, 0, sizeof(out));
    Camellia_ofb128_encrypt(in, out, 20, &ck, iv, &num);
    rt_hex("camellia.ofb128.enc", out, 20);
    rt_hex("camellia.ofb128.enc.iv", iv, 16);
    printf("camellia.ofb128.num=%d\n", num);

    /* CTR: exact block, partial tail, and a resumed counter. */
    rt_fill(iv, 16, 8);
    num = 0;
    memset(ecount, 0, sizeof(ecount));
    memset(out, 0, sizeof(out));
    Camellia_ctr128_encrypt(in, out, 16, &ck, iv, ecount, (unsigned int *)&num);
    rt_hex("camellia.ctr.oneblock.ct", out, 16);
    rt_hex("camellia.ctr.oneblock.iv", iv, 16);
    printf("camellia.ctr.oneblock.num=%d\n", num);

    rt_fill(iv, 16, 8);
    num = 0;
    memset(ecount, 0, sizeof(ecount));
    memset(out, 0, sizeof(out));
    Camellia_ctr128_encrypt(in, out, 35, &ck, iv, ecount, (unsigned int *)&num);
    rt_hex("camellia.ctr.partial.ct", out, 35);
    rt_hex("camellia.ctr.partial.iv", iv, 16);
    rt_hex("camellia.ctr.partial.ecount", ecount, 16);
    printf("camellia.ctr.partial.num=%d\n", num);

    rt_fill(iv, 16, 8);
    num = 4;
    rt_fill(ecount, 16, 11);
    memset(out, 0, sizeof(out));
    Camellia_ctr128_encrypt(in, out, 20, &ck, iv, ecount, (unsigned int *)&num);
    rt_hex("camellia.ctr.resume.ct", out, 20);
    rt_hex("camellia.ctr.resume.ecount", ecount, 16);
    printf("camellia.ctr.resume.num=%d\n", num);
}

static void rt_deflt_cipher(void)
{
    static const char *names[] = {
        "NULL", "AES-128-ECB", "AES-128-CBC", "AES-128-OFB", "AES-128-CFB",
        "AES-128-CTR", "AES-192-CBC", "AES-256-ECB", "CAMELLIA-128-CBC",
        "CAMELLIA-256-CTR", "CAMELLIA-192-ECB", "DES-EDE3-CBC", "DES-EDE-CBC",
        /* The legacy provider's, and absent from the default one: this must answer 0. */
        "DES-CBC", "RC4", "BF-CBC", "CAST5-CBC", "IDEA-CBC", "SEED-CBC"
    };
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char in[32];
    unsigned char out[64];
    char buf[128];
    size_t n;

    rt_fill(key, sizeof(key), 21);
    rt_fill(iv, sizeof(iv), 22);
    rt_fill(in, sizeof(in), 23);

    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);

        snprintf(buf, sizeof(buf), "deflt.%s", names[n]);
        printf("%s.fetched=%d\n", buf, c != NULL);
        if (c == NULL)
            continue;
        printf("%s.keylen=%d\n", buf, EVP_CIPHER_get_key_length(c));
        printf("%s.ivlen=%d\n", buf, EVP_CIPHER_get_iv_length(c));
        printf("%s.blocksize=%d\n", buf, EVP_CIPHER_get_block_size(c));
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outl = 0, finl = 0;

            if (ctx == NULL) {
                printf("%s.ctx=0\n", buf);
                EVP_CIPHER_free(c);
                continue;
            }
            /* The key is passed at the row's own length; the provider rejects any other. */
            if (EVP_EncryptInit_ex(ctx, c, NULL, key, iv) != 1) {
                printf("%s.init=0\n", buf);
            } else if (EVP_EncryptUpdate(ctx, out, &outl, in, 32) != 1) {
                printf("%s.update=0\n", buf);
            } else if (EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1) {
                printf("%s.final=0\n", buf);
            } else {
                rt_hex(buf, out, (size_t)(outl + finl));
            }
            EVP_CIPHER_CTX_free(ctx);
        }
        EVP_CIPHER_free(c);
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

/*
 * The key-wrap family (RFC 3394 and RFC 5649). The block function is the probe's own
 * permutation, so the observation is the wrapping arithmetic and nothing else.
 *
 * What it observes
 * ----------------
 *   * the wrapped bytes, as hex, for each legal length (n = 2..5 64-bit blocks), with the
 *     default IV and with a caller-supplied one;
 *   * the returned length, which is `inlen + 8` for a wrap and `inlen - 8` for an unwrap;
 *   * the refusal arms: a length that is not a multiple of eight, an out-of-range length,
 *     a mismatched IV, and a corrupted AIV or padding. On every refusal the authority
 *     returns 0 and **cleanses** the destination over the length it would have written,
 *     so the destination is pre-filled with a sentinel and printed whole: the zeroed
 *     region and the untouched sentinel are both evidence.
 *   * the RFC 5649 single-block special case, where a padded plaintext of exactly eight
 *     octets takes the ECB path rather than the wrap loop.
 */
static void rt_modes_wrap(void)
{
    unsigned char key = RT_KEY;
    unsigned char in[48];
    unsigned char out[64];
    unsigned char wrapped[64];
    unsigned char iv[8];
    size_t i;

    rt_fill(in, sizeof(in), 21);

    /* ---- RFC 3394 wrap with the default IV, for every legal block count. ---- */
    for (i = 2; i <= 5; i++) {
        size_t ret;
        char name[48];

        memset(out, 0, sizeof(out));
        ret = CRYPTO_128_wrap(&key, NULL, out, in, i * 8, rt_block);
        snprintf(name, sizeof(name), "wrap.wrap.n%u.ret", (unsigned)i);
        printf("%s=%u\n", name, (unsigned)ret);
        snprintf(name, sizeof(name), "wrap.wrap.n%u.ct", (unsigned)i);
        rt_hex(name, out, ret ? ret : 0);
    }

    /* ---- The lengths the authority refuses. ---- */
    {
        static const size_t bad[] = { 0, 7, 8, 15, 17 };

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            char name[48];

            memset(out, 0xcc, sizeof(out));
            printf("wrap.wrap.bad%u.ret=%u\n", (unsigned)bad[i],
                   (unsigned)CRYPTO_128_wrap(&key, NULL, out, in, bad[i], rt_block));
            snprintf(name, sizeof(name), "wrap.wrap.bad%u.out", (unsigned)bad[i]);
            rt_hex(name, out, 32);
        }
    }

    /* ---- A caller-supplied IV, and the mismatched-IV refusal. ---- */
    rt_fill(iv, sizeof(iv), 22);
    memset(wrapped, 0, sizeof(wrapped));
    {
        size_t ret = CRYPTO_128_wrap(&key, iv, wrapped, in, 24, rt_block);

        printf("wrap.wrap.iv.ret=%u\n", (unsigned)ret);
        rt_hex("wrap.wrap.iv.ct", wrapped, ret ? ret : 0);
    }
    {
        unsigned char got[64];
        size_t ret;

        memset(got, 0xcc, sizeof(got));
        ret = CRYPTO_128_unwrap(&key, NULL, got, wrapped, 32, rt_block);
        printf("wrap.unwrap.wrongiv.ret=%u\n", (unsigned)ret);
        rt_hex("wrap.unwrap.wrongiv.out", got, 32);

        memset(got, 0xcc, sizeof(got));
        ret = CRYPTO_128_unwrap(&key, iv, got, wrapped, 32, rt_block);
        printf("wrap.unwrap.rightiv.ret=%u\n", (unsigned)ret);
        rt_hex("wrap.unwrap.rightiv.out", got, ret ? ret : 0);
    }

    /* ---- RFC 5649 wrap_pad, including the eight-octet single-block special case. ---- */
    {
        static const size_t lens[] = { 0, 1, 7, 8, 9, 16, 17, 20, 24 };

        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            size_t ret;
            char name[48];

            memset(out, 0, sizeof(out));
            ret = CRYPTO_128_wrap_pad(&key, NULL, out, in, lens[i], rt_block);
            snprintf(name, sizeof(name), "wrap.pad%u.ret", (unsigned)lens[i]);
            printf("%s=%u\n", name, (unsigned)ret);
            snprintf(name, sizeof(name), "wrap.pad%u.ct", (unsigned)lens[i]);
            rt_hex(name, out, ret ? ret : 0);

            if (ret == 0)
                continue;
            memcpy(wrapped, out, ret);

            memset(out, 0xcc, sizeof(out));
            {
                size_t back = CRYPTO_128_unwrap_pad(&key, NULL, out, wrapped, ret, rt_block);

                snprintf(name, sizeof(name), "wrap.pad%u.roundtrip.ret", (unsigned)lens[i]);
                printf("%s=%u\n", name, (unsigned)back);
                snprintf(name, sizeof(name), "wrap.pad%u.roundtrip.pt", (unsigned)lens[i]);
                rt_hex(name, out, back ? back : 0);
            }

            /* Corrupt the AIV: the check must fail and the destination be cleansed. */
            wrapped[0] ^= 0x01;
            memset(out, 0xcc, sizeof(out));
            {
                size_t back = CRYPTO_128_unwrap_pad(&key, NULL, out, wrapped, ret, rt_block);

                snprintf(name, sizeof(name), "wrap.pad%u.badaiv.ret", (unsigned)lens[i]);
                printf("%s=%u\n", name, (unsigned)back);
                snprintf(name, sizeof(name), "wrap.pad%u.badaiv.out", (unsigned)lens[i]);
                rt_hex(name, out, 32);
            }
            wrapped[0] ^= 0x01;

            /* Corrupt the final padding octet: the padding check must fail. */
            wrapped[ret - 1] ^= 0x01;
            memset(out, 0xcc, sizeof(out));
            {
                size_t back = CRYPTO_128_unwrap_pad(&key, NULL, out, wrapped, ret, rt_block);

                snprintf(name, sizeof(name), "wrap.pad%u.badpad.ret", (unsigned)lens[i]);
                printf("%s=%u\n", name, (unsigned)back);
            }
            wrapped[ret - 1] ^= 0x01;
        }
    }

    /* ---- A caller-supplied RFC 5649 ICV, and its mismatch. ---- */
    {
        unsigned char icv[4];
        unsigned char got[64];
        size_t ret;

        rt_fill(icv, sizeof(icv), 23);
        rt_fill(iv, sizeof(iv), 22);
        memset(wrapped, 0, sizeof(wrapped));
        ret = CRYPTO_128_wrap_pad(&key, icv, wrapped, in, 9, rt_block);
        printf("wrap.pad.icv.ret=%u\n", (unsigned)ret);
        rt_hex("wrap.pad.icv.ct", wrapped, ret ? ret : 0);

        memset(got, 0xcc, sizeof(got));
        ret = CRYPTO_128_unwrap_pad(&key, iv, got, wrapped, 16, rt_block);
        printf("wrap.pad.badicv.ret=%u\n", (unsigned)ret);
        rt_hex("wrap.pad.badicv.out", got, 32);

        memset(got, 0xcc, sizeof(got));
        ret = CRYPTO_128_unwrap_pad(&key, icv, got, wrapped, 16, rt_block);
        printf("wrap.pad.righticv.ret=%u\n", (unsigned)ret);
        rt_hex("wrap.pad.righticv.out", got, ret ? ret : 0);
    }
}

/*
 * GCM. The context is opaque and is only ever obtained from `CRYPTO_gcm128_new`, so the
 * observation is the whole reachable contract: the ciphertext, the tag, the return codes, the
 * buffered-partial-block behaviour under three different call splits, the in-place arm, the
 * AAD-only and empty-plaintext arms, and both tag-verification answers.
 *
 * `CRYPTO_gcm128_encrypt_ctr32`'s `ctr128_f` is the probe's own AES-CTR, which is the same
 * function on both sides; the authority calls it only for its 3 KiB chunk, and the candidate
 * (and the authority's non-chunk path) generate the same keystream, so a long message
 * exercises both.
 */
static void rt_gcm_ctr32(const unsigned char *in, unsigned char *out, size_t blocks,
                         const void *key, const unsigned char ivec[16])
{
    unsigned char ctr[16];
    unsigned char ks[16];
    unsigned int c;
    size_t b;
    int i;

    memcpy(ctr, ivec, 16);
    c = ((unsigned int)ctr[12] << 24) | ((unsigned int)ctr[13] << 16)
        | ((unsigned int)ctr[14] << 8) | (unsigned int)ctr[15];
    for (b = 0; b < blocks; b++) {
        AES_encrypt(ctr, ks, (const AES_KEY *)key);
        for (i = 0; i < 16; i++)
            out[16 * b + i] = in[16 * b + i] ^ ks[i];
        c++;
        ctr[12] = (unsigned char)(c >> 24);
        ctr[13] = (unsigned char)(c >> 16);
        ctr[14] = (unsigned char)(c >> 8);
        ctr[15] = (unsigned char)c;
    }
}

static void rt_gcm128(void)
{
    static const unsigned char gkey[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char iv12[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    AES_KEY aeskey;
    unsigned char in[4096];
    unsigned char out[4096];
    unsigned char ct[4096];
    unsigned char tag[16];
    unsigned char aad[64];
    GCM128_CONTEXT *ctx;

    rt_fill(in, sizeof(in), 31);
    rt_fill(aad, sizeof(aad), 32);

    if (AES_set_encrypt_key(gkey, 128, &aeskey) != 0) {
        printf("gcm.setup=0\n");
        return;
    }
    printf("gcm.setup=1\n");

    /* ---- Encrypt one partial block plus a tail, with AAD, then tag. ---- */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    printf("gcm.enc.aad_ret=%d\n", CRYPTO_gcm128_aad(ctx, aad, 13));
    printf("gcm.enc.ret=%d\n", CRYPTO_gcm128_encrypt(ctx, in, out, 33));
    rt_hex("gcm.enc.ct", out, 33);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.enc.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    /* ---- The same bytes split 5 + 28 and 16 + 1 + 16: one tag, one ciphertext. ---- */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_aad(ctx, aad, 13);
    CRYPTO_gcm128_encrypt(ctx, in, ct, 5);
    CRYPTO_gcm128_encrypt(ctx, in + 5, ct + 5, 28);
    rt_hex("gcm.split.a.ct", ct, 33);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.split.a.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_aad(ctx, aad, 13);
    CRYPTO_gcm128_encrypt(ctx, in, ct, 16);
    CRYPTO_gcm128_encrypt(ctx, in + 16, ct + 16, 1);
    CRYPTO_gcm128_encrypt(ctx, in + 17, ct + 17, 16);
    rt_hex("gcm.split.b.ct", ct, 33);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.split.b.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    /* ---- Empty plaintext, and AAD-only. ---- */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_aad(ctx, aad, 13);
    printf("gcm.empty.ret=%d\n", CRYPTO_gcm128_encrypt(ctx, in, out, 0));
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.empty.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_aad(ctx, aad, 64);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.aadonly.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    /* ---- In-place decryption of a full block plus a tail. ---- */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_aad(ctx, aad, 13);
    CRYPTO_gcm128_encrypt(ctx, in, ct, 33);
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_aad(ctx, aad, 13);
    memcpy(out, ct, 33);
    printf("gcm.dec_inplace.ret=%d\n", CRYPTO_gcm128_decrypt(ctx, out, out, 33));
    rt_hex("gcm.dec_inplace.pt", out, 33);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.dec_inplace.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    /* ---- Tag verification: accept, reject, a NULL tag, and an over-long tag. ---- */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_encrypt(ctx, in, ct, 33);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_decrypt(ctx, ct, out, 33);
    printf("gcm.verify.accept=%d\n", CRYPTO_gcm128_finish(ctx, tag, 16) == 0);
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_decrypt(ctx, ct, out, 33);
    tag[0] ^= 0x01;
    printf("gcm.verify.reject=%d\n", CRYPTO_gcm128_finish(ctx, tag, 16) == 0);
    CRYPTO_gcm128_release(ctx);
    tag[0] ^= 0x01;

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    printf("gcm.finish.nulltag=%d\n", CRYPTO_gcm128_finish(ctx, NULL, 0));
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    printf("gcm.finish.longtag=%d\n", CRYPTO_gcm128_finish(ctx, tag, 17));
    CRYPTO_gcm128_release(ctx);

    /* A truncated tag of 12 bytes. */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_encrypt(ctx, in, ct, 33);
    CRYPTO_gcm128_tag(ctx, tag, 12);
    rt_hex("gcm.tag12", tag, 12);
    CRYPTO_gcm128_release(ctx);

    /* ---- A non-96-bit IV: the GHASH-derived J0. ---- */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, 16);
    CRYPTO_gcm128_encrypt(ctx, in, out, 16);
    rt_hex("gcm.iv16.ct", out, 16);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.iv16.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, 1);
    CRYPTO_gcm128_encrypt(ctx, in, out, 16);
    rt_hex("gcm.iv1.ct", out, 16);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.iv1.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    /* ---- AAD after the message has begun is refused with -2. ---- */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    CRYPTO_gcm128_encrypt(ctx, in, out, 1);
    printf("gcm.aad.late=%d\n", CRYPTO_gcm128_aad(ctx, aad, 1));
    CRYPTO_gcm128_release(ctx);

    /* ---- The ctr32 entry points, including a message past the authority's 3 KiB chunk. ---- */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    printf("gcm.ctr32.ret=%d\n",
           CRYPTO_gcm128_encrypt_ctr32(ctx, in, out, 33, rt_gcm_ctr32));
    rt_hex("gcm.ctr32.ct", out, 33);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.ctr32.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    printf("gcm.ctr32.long.ret=%d\n",
           CRYPTO_gcm128_encrypt_ctr32(ctx, in, out, 4000, rt_gcm_ctr32));
    rt_hex("gcm.ctr32.long.ct", out, 4000);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.ctr32.long.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    printf("gcm.plain.long.ret=%d\n", CRYPTO_gcm128_encrypt(ctx, in, ct, 4000));
    rt_hex("gcm.plain.long.ct", ct, 4000);
    CRYPTO_gcm128_tag(ctx, tag, 16);
    rt_hex("gcm.plain.long.tag", tag, 16);
    CRYPTO_gcm128_release(ctx);

    /* The ctr32 decrypt direction, over a long message produced above. */
    ctx = CRYPTO_gcm128_new(&aeskey, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv12, sizeof(iv12));
    printf("gcm.ctr32.dec.ret=%d\n",
           CRYPTO_gcm128_decrypt_ctr32(ctx, ct, out, 4000, rt_gcm_ctr32));
    rt_hex("gcm.ctr32.dec.pt", out, 4000);
    CRYPTO_gcm128_release(ctx);
}

/*
 * CCM. `CCM128_CONTEXT` is opaque in the public header and this API has no library allocator
 * (`_new`), so the probe supplies the storage itself: a 128-byte aligned buffer is handed to the
 * library, which writes its own 56-byte context into it, and the probe never reads it back. The
 * observation therefore stays at the caller's boundary.
 *
 * The substance is the plan's trap: the message length is fixed before the AAD. `setiv` writes
 * `mlen` into B0's length octets and each body refuses with -1 unless it reconstructs the same
 * length, so the arm observes that refusal and the corrupted tag it leaves behind (the flags
 * byte is not restored), the three AAD-length encodings, the `tag` length refusal, and the
 * `_ccm64` entry points against the plain path through the probe's own CCM stream.
 */
typedef union {
    unsigned char bytes[128];
    unsigned long long align;
} rt_ccm_ctx;

/* The caller's `ccm128_f`: encrypt each block under the 64-bit counter in `ivec`, then fold the
 * ciphertext block into `cmac`. `ivec` already carries the counter (B0's last octet is 1 by the
 * time the body calls this), so the first block uses it as-is and increments afterwards — the
 * same convention the non-streamed path uses. */
static void rt_ccm_stream(const unsigned char *in, unsigned char *out, size_t blocks,
                          const void *key, const unsigned char ivec[16],
                          unsigned char cmac[16])
{
    unsigned char ctr[16];
    unsigned char ks[16];
    size_t b;
    int i;

    memcpy(ctr, ivec, 16);
    for (b = 0; b < blocks; b++) {
        AES_encrypt(ctr, ks, (const AES_KEY *)key);
        for (i = 0; i < 16; i++) {
            out[16 * b + i] = in[16 * b + i] ^ ks[i];
            cmac[i] ^= out[16 * b + i];
        }
        for (i = 15; i >= 8; i--) {
            ctr[i] = (unsigned char)(ctr[i] + 1);
            if (ctr[i] != 0)
                break;
        }
    }
}

static void rt_ccm128(void)
{
    static const unsigned char ckey[16] = {
        0x19, 0xeb, 0xfd, 0xe2, 0xd5, 0x46, 0x8b, 0xa0,
        0xa3, 0x03, 0x1b, 0xde, 0x62, 0x9b, 0x11, 0xfd
    };
    static const unsigned char nonce13[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    static const unsigned char nonce7[7] = {
        0x5a, 0x8a, 0xa4, 0x85, 0xc3, 0x16, 0xe9
    };
    static unsigned char bigaad[70000];
    AES_KEY aeskey;
    rt_ccm_ctx c1, c2;
    unsigned char in[64], out[64], ct[64], back[64], tag[16], tag8[16], aad[80];
    CCM128_CONTEXT *ctx;

    rt_fill(in, sizeof(in), 41);
    rt_fill(aad, sizeof(aad), 42);
    rt_fill(bigaad, sizeof(bigaad), 43);

    if (AES_set_encrypt_key(ckey, 128, &aeskey) != 0) {
        printf("ccm.setup=0\n");
        return;
    }
    printf("ccm.setup=1\n");

    /* ---- 7-octet nonce (L=8), 16-octet tag, AAD, a partial final block. ---- */
    memset(&c1, 0, sizeof(c1));
    ctx = (CCM128_CONTEXT *)&c1;
    CRYPTO_ccm128_init(ctx, 16, 8, &aeskey, (block128_f)AES_encrypt);
    printf("ccm.enc.setiv=%d\n", CRYPTO_ccm128_setiv(ctx, nonce7, sizeof(nonce7), 21));
    CRYPTO_ccm128_aad(ctx, aad, 13);
    printf("ccm.enc.ret=%d\n", CRYPTO_ccm128_encrypt(ctx, in, ct, 21));
    rt_hex("ccm.enc.ct", ct, 21);
    printf("ccm.enc.tag=%u\n", (unsigned)CRYPTO_ccm128_tag(ctx, tag, 16));
    rt_hex("ccm.enc.tagv", tag, 16);

    /* ---- `tag` refuses any length but M. ---- */
    printf("ccm.tag.short=%u\n", (unsigned)CRYPTO_ccm128_tag(ctx, tag, 15));
    printf("ccm.tag.long=%u\n", (unsigned)CRYPTO_ccm128_tag(ctx, tag, 17));

    /* ---- Decrypt round trip, the same tag, and in place. ---- */
    memset(&c2, 0, sizeof(c2));
    ctx = (CCM128_CONTEXT *)&c2;
    CRYPTO_ccm128_init(ctx, 16, 8, &aeskey, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, nonce7, sizeof(nonce7), 21);
    CRYPTO_ccm128_aad(ctx, aad, 13);
    printf("ccm.dec.ret=%d\n", CRYPTO_ccm128_decrypt(ctx, ct, back, 21));
    printf("ccm.dec.match=%d\n", memcmp(back, in, 21) == 0);
    CRYPTO_ccm128_tag(ctx, tag8, 16);
    printf("ccm.dec.tagsame=%d\n", memcmp(tag8, tag, 16) == 0);

    memset(&c2, 0, sizeof(c2));
    memcpy(out, ct, 21);
    ctx = (CCM128_CONTEXT *)&c2;
    CRYPTO_ccm128_init(ctx, 16, 8, &aeskey, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, nonce7, sizeof(nonce7), 21);
    CRYPTO_ccm128_aad(ctx, aad, 13);
    printf("ccm.dec.inplace=%d\n", CRYPTO_ccm128_decrypt(ctx, out, out, 21));
    printf("ccm.dec.inplace.match=%d\n", memcmp(out, in, 21) == 0);

    /* ---- L=2 (13-octet nonce), 8-octet tag, and `aad(0)` as a no-op. ---- */
    memset(&c1, 0, sizeof(c1));
    ctx = (CCM128_CONTEXT *)&c1;
    CRYPTO_ccm128_init(ctx, 8, 2, &aeskey, (block128_f)AES_encrypt);
    printf("ccm2.setiv=%d\n", CRYPTO_ccm128_setiv(ctx, nonce13, sizeof(nonce13), 32));
    CRYPTO_ccm128_aad(ctx, aad, 0);
    CRYPTO_ccm128_aad(ctx, aad, 20);
    printf("ccm2.enc.ret=%d\n", CRYPTO_ccm128_encrypt(ctx, in, out, 32));
    rt_hex("ccm2.enc.ct", out, 32);
    printf("ccm2.tag=%u\n", (unsigned)CRYPTO_ccm128_tag(ctx, tag8, 8));
    rt_hex("ccm2.tagv", tag8, 8);

    memset(&c2, 0, sizeof(c2));
    ctx = (CCM128_CONTEXT *)&c2;
    CRYPTO_ccm128_init(ctx, 8, 2, &aeskey, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, nonce13, sizeof(nonce13), 32);
    CRYPTO_ccm128_aad(ctx, aad, 20);
    CRYPTO_ccm128_encrypt(ctx, in, ct, 32);
    CRYPTO_ccm128_tag(ctx, tag, 8);
    printf("ccm2.aad0.same=%d\n", memcmp(tag, tag8, 8) == 0);

    /* ---- Empty message with AAD only. ---- */
    memset(&c1, 0, sizeof(c1));
    ctx = (CCM128_CONTEXT *)&c1;
    CRYPTO_ccm128_init(ctx, 16, 2, &aeskey, (block128_f)AES_encrypt);
    printf("ccm.empty.setiv=%d\n", CRYPTO_ccm128_setiv(ctx, nonce13, sizeof(nonce13), 0));
    CRYPTO_ccm128_aad(ctx, aad, 20);
    printf("ccm.empty.ret=%d\n", CRYPTO_ccm128_encrypt(ctx, in, out, 0));
    CRYPTO_ccm128_tag(ctx, tag, 16);
    rt_hex("ccm.empty.tagv", tag, 16);

    /* ---- The length mismatch, and the corrupted tag the refusal leaves behind. ---- */
    memset(&c1, 0, sizeof(c1));
    ctx = (CCM128_CONTEXT *)&c1;
    CRYPTO_ccm128_init(ctx, 16, 8, &aeskey, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, nonce7, sizeof(nonce7), 16);
    printf("ccm.mismatch.ret=%d\n", CRYPTO_ccm128_encrypt(ctx, in, out, 15));
    printf("ccm.mismatch.tag=%u\n", (unsigned)CRYPTO_ccm128_tag(ctx, tag, 16));

    /* ---- A nonce shorter than L allows. ---- */
    memset(&c1, 0, sizeof(c1));
    ctx = (CCM128_CONTEXT *)&c1;
    CRYPTO_ccm128_init(ctx, 16, 8, &aeskey, (block128_f)AES_encrypt);
    printf("ccm.short.setiv=%d\n", CRYPTO_ccm128_setiv(ctx, nonce7, 5, 16));

    /* ---- The `_ccm64` entry points, against the plain path. ---- */
    memset(&c1, 0, sizeof(c1));
    ctx = (CCM128_CONTEXT *)&c1;
    CRYPTO_ccm128_init(ctx, 16, 2, &aeskey, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, nonce13, sizeof(nonce13), 48);
    CRYPTO_ccm128_aad(ctx, aad, 20);
    printf("ccm64.enc.ret=%d\n",
           CRYPTO_ccm128_encrypt_ccm64(ctx, in, out, 48, rt_ccm_stream));
    rt_hex("ccm64.enc.ct", out, 48);
    CRYPTO_ccm128_tag(ctx, tag, 16);
    rt_hex("ccm64.enc.tagv", tag, 16);

    memset(&c2, 0, sizeof(c2));
    ctx = (CCM128_CONTEXT *)&c2;
    CRYPTO_ccm128_init(ctx, 16, 2, &aeskey, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, nonce13, sizeof(nonce13), 48);
    CRYPTO_ccm128_aad(ctx, aad, 20);
    CRYPTO_ccm128_encrypt(ctx, in, ct, 48);
    printf("ccm64.plain.same=%d\n", memcmp(ct, out, 48) == 0);
    CRYPTO_ccm128_tag(ctx, tag8, 16);
    printf("ccm64.tag.same=%d\n", memcmp(tag8, tag, 16) == 0);

    memset(&c2, 0, sizeof(c2));
    ctx = (CCM128_CONTEXT *)&c2;
    CRYPTO_ccm128_init(ctx, 16, 2, &aeskey, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, nonce13, sizeof(nonce13), 48);
    CRYPTO_ccm128_aad(ctx, aad, 20);
    printf("ccm64.dec.ret=%d\n",
           CRYPTO_ccm128_decrypt_ccm64(ctx, out, back, 48, rt_ccm_stream));
    printf("ccm64.dec.match=%d\n", memcmp(back, in, 48) == 0);

    /* ---- The AAD-length encodings: 65279 (two octets), 65280 and 70000 (six octets). ---- */
    {
        static const size_t lens[3] = {65279, 65280, 70000};
        int k;

        for (k = 0; k < 3; k++) {
            char name[48];

            memset(&c1, 0, sizeof(c1));
            ctx = (CCM128_CONTEXT *)&c1;
            CRYPTO_ccm128_init(ctx, 16, 2, &aeskey, (block128_f)AES_encrypt);
            CRYPTO_ccm128_setiv(ctx, nonce13, sizeof(nonce13), 0);
            CRYPTO_ccm128_aad(ctx, bigaad, lens[k]);
            CRYPTO_ccm128_encrypt(ctx, in, out, 0);
            CRYPTO_ccm128_tag(ctx, tag, 16);
            snprintf(name, sizeof(name), "ccm.aadlen.%u", (unsigned)lens[k]);
            rt_hex(name, tag, 16);
        }
    }
}

/*
 * XTS. The context is caller-populated — the public header only forward-declares
 * `XTS128_CONTEXT` — so the probe supplies the four fields itself. `block1` is the data-unit
 * cipher and, for decryption, the caller hands it the *decrypt* function
 * (`crypto/evp/e_aes.c:303`); `block2` is always the tweak cipher's encrypt. The arm observes
 * the tweak advance over several blocks, both ciphertext-stealing directions, the round trip and
 * the short-data-unit refusal.
 */
typedef struct {
    void *key1;
    void *key2;
    block128_f block1;
    block128_f block2;
} rt_xts_ctx;

static void rt_xts128(void)
{
    static const unsigned char xk1[16] = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
    };
    static const unsigned char xk2[16] = {
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
    };
    static const unsigned char xiv[16] = {
        0x33, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const size_t lens[6] = {16, 17, 31, 32, 48, 49};
    AES_KEY ek1, ek2, dk1;
    rt_xts_ctx xe, xd;
    unsigned char in[64], ct[64], back[64], out[64];
    int k;

    rt_fill(in, sizeof(in), 51);

    if (AES_set_encrypt_key(xk1, 128, &ek1) != 0 || AES_set_encrypt_key(xk2, 128, &ek2) != 0
        || AES_set_decrypt_key(xk1, 128, &dk1) != 0) {
        printf("xts.setup=0\n");
        return;
    }
    printf("xts.setup=1\n");

    xe.key1 = &ek1;
    xe.key2 = &ek2;
    xe.block1 = (block128_f)AES_encrypt;
    xe.block2 = (block128_f)AES_encrypt;
    xd.key1 = &dk1;
    xd.key2 = &ek2;
    xd.block1 = (block128_f)rt_aes_dec_block;
    xd.block2 = (block128_f)AES_encrypt;

    printf("xts.short.enc=%d\n",
           CRYPTO_xts128_encrypt((const XTS128_CONTEXT *)&xe, xiv, in, out, 15, 1));
    printf("xts.short.dec=%d\n",
           CRYPTO_xts128_encrypt((const XTS128_CONTEXT *)&xd, xiv, in, out, 15, 0));

    for (k = 0; k < 6; k++) {
        char name[48];
        size_t n = lens[k];
        int r;

        r = CRYPTO_xts128_encrypt((const XTS128_CONTEXT *)&xe, xiv, in, ct, n, 1);
        snprintf(name, sizeof(name), "xts.enc%u.ret", (unsigned)n);
        printf("%s=%d\n", name, r);
        snprintf(name, sizeof(name), "xts.enc%u.ct", (unsigned)n);
        rt_hex(name, ct, n);

        r = CRYPTO_xts128_encrypt((const XTS128_CONTEXT *)&xd, xiv, ct, back, n, 0);
        snprintf(name, sizeof(name), "xts.dec%u.ret", (unsigned)n);
        printf("%s=%d\n", name, r);
        printf("xts.dec%u.match=%d\n", (unsigned)n, memcmp(back, in, n) == 0);
    }

    /* A three-block data unit encrypted and decrypted in place. */
    memcpy(out, in, 48);
    printf("xts.inplace.enc=%d\n",
           CRYPTO_xts128_encrypt((const XTS128_CONTEXT *)&xe, xiv, out, out, 48, 1));
    rt_hex("xts.inplace.ct", out, 48);
    printf("xts.inplace.dec=%d\n",
           CRYPTO_xts128_encrypt((const XTS128_CONTEXT *)&xd, xiv, out, out, 48, 0));
    printf("xts.inplace.match=%d\n", memcmp(out, in, 48) == 0);
}

/*
 * OCB. The context is opaque and allocated by the library, so the probe only ever holds the
 * pointer `CRYPTO_ocb128_new` returns (and caller storage for `copy_ctx`). OCB has no `num`
 * parameter; the partial-final-block accounting is observable through the tag. The arm drives
 * both arms of the bulk loop: with a NULL `stream` the per-block path runs, and with the
 * probe's own `ocb128_f` the streamed path runs — the stream is a caller-supplied pointer, not
 * a host-selected dispatch like GCM's `gcm_get_funcs`, so the two are comparable and must agree.
 * It also exercises `setiv`'s refusals, the `finish`/`tag` length refusals, the empty and
 * AAD-only arms, in-place decryption, `copy_ctx`, and re-initialisation between messages.
 */
static unsigned rt_ocb_ntz(size_t n)
{
    unsigned cnt = 0;

    while ((n & 1) == 0) {
        n >>= 1;
        cnt++;
    }
    return cnt;
}

/* The probe-local `ocb128_f`, encrypt direction: the authority's own per-block body, so the
 * streamed and per-block arms are the same arithmetic and must agree byte for byte. */
static void rt_ocb_stream_enc(const unsigned char *in, unsigned char *out, size_t blocks,
                              const void *key, size_t start_block_num,
                              unsigned char offset_i[16], const unsigned char L_[][16],
                              unsigned char checksum[16])
{
    size_t b, i;

    for (b = 0; b < blocks; b++) {
        const unsigned char *lookup = L_[rt_ocb_ntz(start_block_num + b)];
        unsigned char tmp[16];

        for (i = 0; i < 16; i++) {
            offset_i[i] ^= lookup[i];
            tmp[i] = in[16 * b + i];
            checksum[i] ^= tmp[i];
            tmp[i] ^= offset_i[i];
        }
        AES_encrypt(tmp, tmp, (const AES_KEY *)key);
        for (i = 0; i < 16; i++) {
            tmp[i] ^= offset_i[i];
            out[16 * b + i] = tmp[i];
        }
    }
}

/* The decrypt direction: the same offsets, the data cipher inverted. */
static void rt_ocb_stream_dec(const unsigned char *in, unsigned char *out, size_t blocks,
                              const void *key, size_t start_block_num,
                              unsigned char offset_i[16], const unsigned char L_[][16],
                              unsigned char checksum[16])
{
    size_t b, i;

    for (b = 0; b < blocks; b++) {
        const unsigned char *lookup = L_[rt_ocb_ntz(start_block_num + b)];
        unsigned char tmp[16];

        for (i = 0; i < 16; i++) {
            offset_i[i] ^= lookup[i];
            tmp[i] = in[16 * b + i] ^ offset_i[i];
        }
        AES_decrypt(tmp, tmp, (const AES_KEY *)key);
        for (i = 0; i < 16; i++) {
            tmp[i] ^= offset_i[i];
            checksum[i] ^= tmp[i];
            out[16 * b + i] = tmp[i];
        }
    }
}

static void rt_ocb128(void)
{
    static const unsigned char okey[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char iv12[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };
    union {
        unsigned char bytes[320];
        unsigned long long align;
    } store;
    AES_KEY ek, dk;
    OCB128_CONTEXT *ctx;
    unsigned char in[64], out[64], ct[64], back[64], tag[16], tag2[16], aad[32];

    rt_fill(in, sizeof(in), 61);
    rt_fill(aad, sizeof(aad), 62);

    if (AES_set_encrypt_key(okey, 128, &ek) != 0 || AES_set_decrypt_key(okey, 128, &dk) != 0) {
        printf("ocb.setup=0\n");
        return;
    }
    printf("ocb.setup=1\n");

    /* ---- `setiv`'s refusals: len 0 and 16, taglen 0 and 17, then the accepted call. ---- */
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    printf("ocb.setiv.len0=%d\n", CRYPTO_ocb128_setiv(ctx, iv12, 0, 16));
    printf("ocb.setiv.len16=%d\n", CRYPTO_ocb128_setiv(ctx, iv12, 16, 16));
    printf("ocb.setiv.tag0=%d\n", CRYPTO_ocb128_setiv(ctx, iv12, 12, 0));
    printf("ocb.setiv.tag17=%d\n", CRYPTO_ocb128_setiv(ctx, iv12, 12, 17));
    printf("ocb.setiv.ok=%d\n", CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16));

    /* ---- AAD and a partial final block, then the tag. ---- */
    printf("ocb.enc.aad=%d\n", CRYPTO_ocb128_aad(ctx, aad, 13));
    printf("ocb.enc.ret=%d\n", CRYPTO_ocb128_encrypt(ctx, in, out, 33));
    rt_hex("ocb.enc.ct", out, 33);
    printf("ocb.tag.ret=%d\n", CRYPTO_ocb128_tag(ctx, tag, 16));
    rt_hex("ocb.enc.tag", tag, 16);
    CRYPTO_ocb128_cleanup(ctx);

    /* ---- The same bytes split 16 + 17: one ciphertext, one tag. ---- */
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    printf("ocb.split.setiv=%d\n", CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16));
    CRYPTO_ocb128_aad(ctx, aad, 13);
    CRYPTO_ocb128_encrypt(ctx, in, ct, 16);
    printf("ocb.split.ret=%d\n", CRYPTO_ocb128_encrypt(ctx, in + 16, ct + 16, 17));
    rt_hex("ocb.split.ct", ct, 33);
    CRYPTO_ocb128_tag(ctx, tag2, 16);
    printf("ocb.split.same=%d\n", memcmp(ct, out, 33) == 0 && memcmp(tag2, tag, 16) == 0);
    CRYPTO_ocb128_cleanup(ctx);

    /* ---- Empty plaintext (AAD present), and AAD-only. ---- */
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16);
    CRYPTO_ocb128_aad(ctx, aad, 13);
    printf("ocb.empty.ret=%d\n", CRYPTO_ocb128_encrypt(ctx, in, out, 0));
    CRYPTO_ocb128_tag(ctx, tag, 16);
    rt_hex("ocb.empty.tag", tag, 16);
    CRYPTO_ocb128_cleanup(ctx);

    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16);
    CRYPTO_ocb128_aad(ctx, aad, 32);
    CRYPTO_ocb128_tag(ctx, tag, 16);
    rt_hex("ocb.aadonly.tag", tag, 16);
    CRYPTO_ocb128_cleanup(ctx);

    /* ---- Tag lengths 1 and 8, and the refusals at 0 and 17; `finish` shares the guard. ---- */
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16);
    CRYPTO_ocb128_encrypt(ctx, in, out, 33);
    CRYPTO_ocb128_tag(ctx, tag, 16);
    printf("ocb.tag.1=%d\n", CRYPTO_ocb128_tag(ctx, tag2, 1));
    rt_hex("ocb.tag.1v", tag2, 1);
    printf("ocb.tag.8=%d\n", CRYPTO_ocb128_tag(ctx, tag2, 8));
    rt_hex("ocb.tag.8v", tag2, 8);
    printf("ocb.tag.0=%d\n", CRYPTO_ocb128_tag(ctx, tag2, 0));
    printf("ocb.tag.17=%d\n", CRYPTO_ocb128_tag(ctx, tag2, 17));
    printf("ocb.finish.0=%d\n", CRYPTO_ocb128_finish(ctx, tag2, 0));
    printf("ocb.finish.17=%d\n", CRYPTO_ocb128_finish(ctx, tag2, 17));
    printf("ocb.finish.accept=%d\n", CRYPTO_ocb128_finish(ctx, tag, 16));
    memcpy(tag2, tag, 16);
    tag2[0] ^= 0x80;
    printf("ocb.finish.reject=%d\n", CRYPTO_ocb128_finish(ctx, tag2, 16) != 0);
    CRYPTO_ocb128_cleanup(ctx);

    /* ---- In-place decryption of the 33-byte arm, then tag verification. ---- */
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16);
    CRYPTO_ocb128_aad(ctx, aad, 13);
    printf("ocb.inplace.enc=%d\n", CRYPTO_ocb128_encrypt(ctx, in, ct, 33));
    CRYPTO_ocb128_tag(ctx, tag, 16);
    CRYPTO_ocb128_cleanup(ctx);

    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16);
    CRYPTO_ocb128_aad(ctx, aad, 13);
    memcpy(back, ct, 33);
    printf("ocb.inplace.dec=%d\n", CRYPTO_ocb128_decrypt(ctx, back, back, 33));
    rt_hex("ocb.inplace.pt", back, 33);
    printf("ocb.inplace.match=%d\n", memcmp(back, in, 33) == 0);
    printf("ocb.verify.accept=%d\n", CRYPTO_ocb128_finish(ctx, tag, 16) == 0);
    CRYPTO_ocb128_cleanup(ctx);

    /* ---- The streamed arm (a caller-supplied `ocb128_f`), both directions. ---- */
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt,
                            rt_ocb_stream_enc);
    printf("ocb.stream.setiv=%d\n", CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16));
    CRYPTO_ocb128_aad(ctx, aad, 13);
    printf("ocb.stream.enc=%d\n", CRYPTO_ocb128_encrypt(ctx, in, out, 33));
    rt_hex("ocb.stream.ct", out, 33);
    CRYPTO_ocb128_tag(ctx, tag2, 16);
    rt_hex("ocb.stream.tag", tag2, 16);
    printf("ocb.stream.same=%d\n", memcmp(out, ct, 33) == 0 && memcmp(tag2, tag, 16) == 0);
    CRYPTO_ocb128_cleanup(ctx);

    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt,
                            rt_ocb_stream_dec);
    CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16);
    CRYPTO_ocb128_aad(ctx, aad, 13);
    printf("ocb.stream.dec=%d\n", CRYPTO_ocb128_decrypt(ctx, ct, back, 33));
    printf("ocb.stream.dec.match=%d\n", memcmp(back, in, 33) == 0);
    printf("ocb.stream.dec.accept=%d\n", CRYPTO_ocb128_finish(ctx, tag, 16) == 0);
    CRYPTO_ocb128_cleanup(ctx);

    /* ---- `copy_ctx` carries the L-table to caller storage. ---- */
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16);
    CRYPTO_ocb128_aad(ctx, aad, 13);
    CRYPTO_ocb128_encrypt(ctx, in, out, 33);
    CRYPTO_ocb128_tag(ctx, tag2, 16);
    memset(&store, 0, sizeof(store));
    printf("ocb.copy.ret=%d\n",
           CRYPTO_ocb128_copy_ctx((OCB128_CONTEXT *)&store, ctx, &ek, &dk));
    printf("ocb.copy.tag=%d\n", CRYPTO_ocb128_tag((OCB128_CONTEXT *)&store, tag, 16));
    printf("ocb.copy.same=%d\n", memcmp(tag, tag2, 16) == 0);
    CRYPTO_ocb128_cleanup((OCB128_CONTEXT *)&store);
    CRYPTO_ocb128_cleanup(ctx);

    /* ---- Re-initialisation between messages on one context. ---- */
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16);
    CRYPTO_ocb128_encrypt(ctx, in, out, 16);
    CRYPTO_ocb128_tag(ctx, tag, 16);
    printf("ocb.reinit.setiv=%d\n", CRYPTO_ocb128_setiv(ctx, iv12, sizeof(iv12), 16));
    CRYPTO_ocb128_encrypt(ctx, in, out, 16);
    CRYPTO_ocb128_tag(ctx, tag2, 16);
    printf("ocb.reinit.same=%d\n", memcmp(tag, tag2, 16) == 0);
    CRYPTO_ocb128_cleanup(ctx);
}

/*
 * The default provider's AES key-wrap rows. D223's `rt_deflt_cipher` arm drives the generic rows
 * through `EVP_CIPHER_fetch`; the wrap rows are their own engine (`cipher_aes_wrp.c`), so this arm
 * observes them: the four properties `get_params` publishes, the wrapped bytes through the
 * provider, the refusal of a length the construction rejects, the padding row's rounding, and —
 * the point of having one RFC 3394 implementation in the crate — that the provider's answer is the
 * low-level `CRYPTO_128_wrap` answer byte for byte. The alias spellings are taken verbatim from
 * `prov/names.h` and must resolve to the same row.
 */
static void rt_deflt_wrap(void)
{
    static const char *names[] = {
        "AES-128-WRAP", "AES-192-WRAP", "AES-256-WRAP",
        "AES-128-WRAP-PAD", "AES-192-WRAP-PAD", "AES-256-WRAP-PAD",
        "AES-128-WRAP-INV", "AES-192-WRAP-INV", "AES-256-WRAP-INV",
        "AES-128-WRAP-PAD-INV", "AES-192-WRAP-PAD-INV", "AES-256-WRAP-PAD-INV",
        /* The three alias spellings `prov/names.h` publishes for these rows. */
        "id-aes128-wrap", "AES256-WRAP-PAD", "AES128-WRAP-INV"
    };
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char in[32];
    unsigned char out[64];
    unsigned char low[64];
    char buf[128];
    AES_KEY aeskey;
    size_t n;

    rt_fill(key, sizeof(key), 71);
    rt_fill(iv, sizeof(iv), 72);
    rt_fill(in, sizeof(in), 73);

    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);

        snprintf(buf, sizeof(buf), "defltwrap.%s", names[n]);
        printf("%s.fetched=%d\n", buf, c != NULL);
        if (c == NULL)
            continue;
        printf("%s.keylen=%d\n", buf, EVP_CIPHER_get_key_length(c));
        printf("%s.ivlen=%d\n", buf, EVP_CIPHER_get_iv_length(c));
        printf("%s.blocksize=%d\n", buf, EVP_CIPHER_get_block_size(c));
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outl = 0, finl = 0;

            if (ctx == NULL) {
                printf("%s.ctx=0\n", buf);
                EVP_CIPHER_free(c);
                continue;
            }
            if (EVP_EncryptInit_ex(ctx, c, NULL, key, iv) != 1) {
                printf("%s.init=0\n", buf);
            } else if (EVP_EncryptUpdate(ctx, out, &outl, in, 24) != 1) {
                printf("%s.update=0\n", buf);
            } else if (EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1) {
                printf("%s.final=0\n", buf);
            } else {
                rt_hex(buf, out, (size_t)(outl + finl));
            }
            EVP_CIPHER_CTX_free(ctx);
        }
        EVP_CIPHER_free(c);
    }

    /* The provider's answer is the low-level answer, for both directions and both constructions. */
    if (AES_set_encrypt_key(key, 128, &aeskey) == 0) {
        static const size_t lens[2] = {16, 24};
        int k;

        for (k = 0; k < 2; k++) {
            size_t m = lens[k];
            size_t lowlen = CRYPTO_128_wrap(&aeskey, iv, low, in, m, (block128_f)AES_encrypt);
            EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-WRAP", NULL);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outl = 0;

            snprintf(buf, sizeof(buf), "defltwrap.eq%u", (unsigned)m);
            if (c == NULL || ctx == NULL) {
                printf("%s.fetched=0\n", buf);
            } else if (EVP_EncryptInit_ex(ctx, c, NULL, key, iv) != 1
                       || EVP_EncryptUpdate(ctx, out, &outl, in, (int)m) != 1) {
                printf("%s.init=0\n", buf);
            } else {
                printf("%s.same=%d\n", buf, (size_t)outl == lowlen && memcmp(out, low, lowlen) == 0);
            }
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
            if (c != NULL)
                EVP_CIPHER_free(c);
        }
    }

    /* The padding row rounds a 21-byte input up, and the plain row refuses a length that is not
     * a multiple of eight. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-WRAP-PAD", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0;

        if (c != NULL && ctx != NULL && EVP_EncryptInit_ex(ctx, c, NULL, key, iv) == 1
            && EVP_EncryptUpdate(ctx, out, &outl, in, 21) == 1) {
            rt_hex("defltwrap.pad21", out, (size_t)outl);
        } else {
            printf("defltwrap.pad21=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-WRAP", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0;

        if (c != NULL && ctx != NULL && EVP_EncryptInit_ex(ctx, c, NULL, key, iv) == 1)
            printf("defltwrap.badlen=%d\n", EVP_EncryptUpdate(ctx, out, &outl, in, 21));
        else
            printf("defltwrap.badlen=0\n");
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }
}

/*
 * The default provider's CBC-CTS rows (AES and Camellia). Ciphertext stealing is not an AEAD:
 * there is no tag and no AAD, and the message is not a stream of block-mode calls. What the arm
 * observes is therefore the row's shape (`keylen`/`ivlen`/`blocksize`), the three variants
 * (`CS1`/`CS2`/`CS3`) applied to a one-block-plus-a-partial-block message, the round trip in
 * each, the empty-message and short-message refusals, and the one-shot rule (a second update is
 * refused). The variants are the construction, so all three are driven for every row.
 */
static void rt_deflt_cts(void)
{
    static const char *names[] = {
        "AES-128-CBC-CTS", "AES-192-CBC-CTS", "AES-256-CBC-CTS",
        "CAMELLIA-128-CBC-CTS", "CAMELLIA-192-CBC-CTS", "CAMELLIA-256-CBC-CTS"
    };
    static const char *cmode_names[] = { "CS1", "CS2", "CS3" };
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char in[48];
    unsigned char out[64];
    unsigned char back[64];
    char buf[160];
    size_t n, m;

    rt_fill(key, sizeof(key), 81);
    rt_fill(iv, sizeof(iv), 82);
    rt_fill(in, sizeof(in), 83);

    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);

        snprintf(buf, sizeof(buf), "defltcts.%s", names[n]);
        printf("%s.fetched=%d\n", buf, c != NULL);
        if (c == NULL)
            continue;
        printf("%s.keylen=%d\n", buf, EVP_CIPHER_get_key_length(c));
        printf("%s.ivlen=%d\n", buf, EVP_CIPHER_get_iv_length(c));
        printf("%s.blocksize=%d\n", buf, EVP_CIPHER_get_block_size(c));
        EVP_CIPHER_free(c);
    }

    /* The three variants, on a 31-byte message (one full block plus fifteen octets). */
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        for (m = 0; m < 3; m++) {
            EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);
            EVP_CIPHER_CTX *ctx;
            OSSL_PARAM params[2];
            int outl = 0, finl = 0;

            snprintf(buf, sizeof(buf), "defltcts.%s.%s", names[n], cmode_names[m]);
            if (c == NULL) {
                printf("%s.fetched=0\n", buf);
                continue;
            }
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE,
                                                         (char *)cmode_names[m], 0);
            params[1] = OSSL_PARAM_construct_end();
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == NULL || EVP_EncryptInit_ex2(ctx, c, key, iv, params) != 1) {
                printf("%s.init=0\n", buf);
            } else if (EVP_EncryptUpdate(ctx, out, &outl, in, 31) != 1
                       || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1) {
                printf("%s.enc=0\n", buf);
            } else {
                rt_hex(buf, out, (size_t)(outl + finl));
                /* The getter must answer the variant that was set. */
                {
                    char mode[8] = { 0 };
                    OSSL_PARAM gp[2];

                    gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, mode, sizeof(mode));
                    gp[1] = OSSL_PARAM_construct_end();
                    printf("%s.getmode=%s\n", buf,
                           EVP_CIPHER_CTX_get_params(ctx, gp) == 1 ? mode : "?");
                }
            }
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);

            /* The round trip, through the same variant. */
            ctx = EVP_CIPHER_CTX_new();
            if (ctx != NULL && EVP_DecryptInit_ex2(ctx, c, key, iv, params) == 1) {
                int decl = 0, defl = 0;

                if (EVP_DecryptUpdate(ctx, back, &decl, out, outl + finl) == 1
                    && EVP_DecryptFinal_ex(ctx, back + decl, &defl) == 1) {
                    printf("%s.roundtrip=%d\n", buf,
                           (size_t)(decl + defl) == 31 && memcmp(back, in, 31) == 0);
                } else {
                    printf("%s.roundtrip=0\n", buf);
                }
            } else {
                printf("%s.roundtrip=0\n", buf);
            }
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_free(c);
        }
    }

    /* The refusals: a message shorter than one block, and a second update on a one-shot row. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC-CTS", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0;

        if (c != NULL && ctx != NULL && EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) == 1) {
            printf("defltcts.short=%d\n", EVP_EncryptUpdate(ctx, out, &outl, in, 15));
            printf("defltcts.empty=%d\n", EVP_EncryptUpdate(ctx, out, &outl, in, 0));
            printf("defltcts.first=%d\n", EVP_EncryptUpdate(ctx, out, &outl, in, 31));
            printf("defltcts.second=%d\n", EVP_EncryptUpdate(ctx, out, &outl, in, 31));
        } else {
            printf("defltcts.short=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The provider's answer is the landed low-level answer, for the CS1 and CS3 variants. */
    {
        AES_KEY ek;
        unsigned char low[64];
        unsigned char ivec[16];
        static const struct { const char *mode; int nist; } arms[2] = {
            { "CS1", 1 }, { "CS3", 0 }
        };
        size_t k;

        if (AES_set_encrypt_key(key, 128, &ek) == 0) {
            for (k = 0; k < 2; k++) {
                EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC-CTS", NULL);
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                OSSL_PARAM params[2];
                int outl = 0, finl = 0;
                size_t lowlen;

                memcpy(ivec, iv, 16);
                if (arms[k].nist)
                    lowlen = CRYPTO_nistcts128_encrypt(in, low, 31, &ek, ivec, rt_cbc);
                else
                    lowlen = CRYPTO_cts128_encrypt(in, low, 31, &ek, ivec, rt_cbc);
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE,
                                                             (char *)arms[k].mode, 0);
                params[1] = OSSL_PARAM_construct_end();
                snprintf(buf, sizeof(buf), "defltcts.eq%s", arms[k].mode);
                if (c == NULL || ctx == NULL || lowlen != 31
                    || EVP_EncryptInit_ex2(ctx, c, key, iv, params) != 1
                    || EVP_EncryptUpdate(ctx, out, &outl, in, 31) != 1
                    || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1)
                    printf("%s.same=0\n", buf);
                else
                    printf("%s.same=%d\n", buf,
                           (size_t)(outl + finl) == lowlen && memcmp(out, low, lowlen) == 0);
                if (ctx != NULL)
                    EVP_CIPHER_CTX_free(ctx);
                if (c != NULL)
                    EVP_CIPHER_free(c);
            }
        }
    }
}

/*
 * The default provider's AES-XTS rows. XTS is defined over a data unit, so the row's block size is
 * one and the EVP layer treats it as a stream; the observations are therefore the row's shape
 * (`keylen` 32/64, `ivlen` 16, `blocksize` 1), the ciphertext at the lengths that exercise the
 * tweak doubling and both ciphertext-stealing arms, the round trip in each direction, the
 * duplicated-key refusal, the short-data-unit refusal, and finally the provider answer against
 * the landed low-level `CRYPTO_xts128_encrypt`.
 */
static void rt_deflt_xts(void)
{
    static const char *names[] = {
        "AES-128-XTS", "AES-256-XTS",
        /* The OID spellings `prov/names.h` publishes second. */
        "1.3.111.2.1619.0.1.1", "1.3.111.2.1619.0.1.2"
    };
    static const size_t lens[] = { 16, 17, 31, 32, 48, 49 };
    unsigned char key[64];
    unsigned char iv[16];
    unsigned char in[64];
    unsigned char out[80];
    unsigned char back[80];
    unsigned char low[80];
    char buf[160];
    size_t n, k;

    rt_fill(key, sizeof(key), 91);
    rt_fill(iv, sizeof(iv), 92);
    rt_fill(in, sizeof(in), 93);

    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);

        snprintf(buf, sizeof(buf), "defltxts.%s", names[n]);
        printf("%s.fetched=%d\n", buf, c != NULL);
        if (c == NULL)
            continue;
        printf("%s.keylen=%d\n", buf, EVP_CIPHER_get_key_length(c));
        printf("%s.ivlen=%d\n", buf, EVP_CIPHER_get_iv_length(c));
        printf("%s.blocksize=%d\n", buf, EVP_CIPHER_get_block_size(c));
        EVP_CIPHER_free(c);
    }

    for (n = 0; n < 2; n++) {
        for (k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
            EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outl = 0, finl = 0, decl = 0, defl = 0;
            size_t len = lens[k];

            snprintf(buf, sizeof(buf), "defltxts.%s.len%u", names[n], (unsigned)len);
            if (c == NULL || ctx == NULL || EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) != 1
                || EVP_EncryptUpdate(ctx, out, &outl, in, (int)len) != 1
                || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1) {
                printf("%s.enc=0\n", buf);
            } else {
                rt_hex(buf, out, (size_t)(outl + finl));
            }
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
            ctx = EVP_CIPHER_CTX_new();
            if (c != NULL && ctx != NULL && EVP_DecryptInit_ex2(ctx, c, key, iv, NULL) == 1
                && EVP_DecryptUpdate(ctx, back, &decl, out, outl + finl) == 1
                && EVP_DecryptFinal_ex(ctx, back + decl, &defl) == 1)
                printf("%s.roundtrip=%d\n", buf,
                       (size_t)(decl + defl) == len && memcmp(back, in, len) == 0);
            else
                printf("%s.roundtrip=0\n", buf);
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
            if (c != NULL)
                EVP_CIPHER_free(c);
        }
    }

    /* The refusals: a data unit shorter than one block, and two equal key halves. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-XTS", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0;

        if (c != NULL && ctx != NULL && EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) == 1)
            printf("defltxts.short=%d\n", EVP_EncryptUpdate(ctx, out, &outl, in, 15));
        else
            printf("defltxts.short=0\n");
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }
    {
        unsigned char dup[32];
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-XTS", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        memcpy(dup, key, 16);
        memcpy(dup + 16, key, 16);
        if (c != NULL && ctx != NULL)
            printf("defltxts.dupkeys=%d\n", EVP_EncryptInit_ex2(ctx, c, dup, iv, NULL));
        else
            printf("defltxts.dupkeys=0\n");
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The provider's answer is the landed low-level answer, for two data units. */
    {
        AES_KEY k1, k2;
        rt_xts_ctx x;
        static const size_t eq[] = { 32, 33 };

        if (AES_set_encrypt_key(key, 128, &k1) == 0
            && AES_set_encrypt_key(key + 16, 128, &k2) == 0) {
            x.key1 = &k1;
            x.key2 = &k2;
            x.block1 = (block128_f)rt_aes_block;
            x.block2 = (block128_f)rt_aes_block;
            for (k = 0; k < 2; k++) {
                EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-XTS", NULL);
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                int outl = 0, finl = 0;
                size_t len = eq[k];

                CRYPTO_xts128_encrypt((const XTS128_CONTEXT *)&x, iv, in, low, len, 1);
                snprintf(buf, sizeof(buf), "defltxts.eq%u", (unsigned)len);
                if (c == NULL || ctx == NULL
                    || EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) != 1
                    || EVP_EncryptUpdate(ctx, out, &outl, in, (int)len) != 1
                    || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1)
                    printf("%s.same=0\n", buf);
                else
                    printf("%s.same=%d\n", buf,
                           (size_t)(outl + finl) == len && memcmp(out, low, len) == 0);
                if (ctx != NULL)
                    EVP_CIPHER_CTX_free(ctx);
                if (c != NULL)
                    EVP_CIPHER_free(c);
            }
        }
    }
}

/*
 * The default provider's AES-OCB rows. OCB buffers AAD and data identically and sets the IV
 * lazily on the first data or AAD call, so the observations are: each row's shape; a 33-byte
 * message (two full blocks plus one octet, so the partial-final-block arm is taken) with 13 bytes
 * of AAD, the ciphertext and the tag; the decrypt round trip; the tag rejection; the
 * empty-plaintext and AAD-only arms; the IV-length window (1..15) from both sides and the tag
 * length's own window; and finally the provider answer against the landed low-level
 * `CRYPTO_ocb128_*`. `prov/names.h` publishes one spelling per row and no OID, so the name the
 * fetch resolves is the name the table carries.
 */
static void rt_deflt_ocb(void)
{
    static const char *names[] = { "AES-256-OCB", "AES-192-OCB", "AES-128-OCB" };
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char in[48];
    unsigned char aad[20];
    unsigned char out[80];
    unsigned char back[80];
    unsigned char tag[16];
    unsigned char bad[16];
    char buf[160];
    char nbuf[176];
    size_t n;

    rt_fill(key, sizeof(key), 101);
    rt_fill(iv, sizeof(iv), 102);
    rt_fill(in, sizeof(in), 103);
    rt_fill(aad, sizeof(aad), 104);

    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);

        snprintf(buf, sizeof(buf), "defltocb.%s", names[n]);
        printf("%s.fetched=%d\n", buf, c != NULL);
        if (c == NULL)
            continue;
        printf("%s.keylen=%d\n", buf, EVP_CIPHER_get_key_length(c));
        printf("%s.ivlen=%d\n", buf, EVP_CIPHER_get_iv_length(c));
        printf("%s.blocksize=%d\n", buf, EVP_CIPHER_get_block_size(c));
        EVP_CIPHER_free(c);
    }

    /* The 33-byte message with 13 bytes of AAD, per row: ciphertext, tag, round trip, reject. */
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);
        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *dctx = NULL;
        int outl = 0, finl = 0, aadl = 0, decl = 0, defl = 0;

        snprintf(buf, sizeof(buf), "defltocb.%s", names[n]);
        if (c == NULL || ectx == NULL || EVP_EncryptInit_ex2(ectx, c, key, iv, NULL) != 1
            || EVP_EncryptUpdate(ectx, NULL, &aadl, aad, 13) != 1
            || EVP_EncryptUpdate(ectx, out, &outl, in, 33) != 1
            || EVP_EncryptFinal_ex(ectx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("%s.enc=0\n", buf);
        } else {
            printf("%s.aad=%d\n", buf, aadl);
            printf("%s.ctlen=%d\n", buf, outl + finl);
            snprintf(nbuf, sizeof(nbuf), "%s.ct", buf);
            rt_hex(nbuf, out, (size_t)(outl + finl));
            snprintf(nbuf, sizeof(nbuf), "%s.tag", buf);
            rt_hex(nbuf, tag, 16);
        }
        if (ectx != NULL)
            EVP_CIPHER_CTX_free(ectx);

        /* The round trip, and then the same bytes with one tag bit flipped. */
        dctx = EVP_CIPHER_CTX_new();
        if (c != NULL && dctx != NULL && EVP_DecryptInit_ex2(dctx, c, key, iv, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1
            && EVP_DecryptUpdate(dctx, NULL, &aadl, aad, 13) == 1
            && EVP_DecryptUpdate(dctx, back, &decl, out, outl + finl) == 1) {
            printf("%s.accept=%d\n", buf,
                   EVP_DecryptFinal_ex(dctx, back + decl, &defl) == 1
                   && (size_t)(decl + defl) == 33 && memcmp(back, in, 33) == 0);
        } else {
            printf("%s.accept=0\n", buf);
        }
        if (dctx != NULL)
            EVP_CIPHER_CTX_free(dctx);

        memcpy(bad, tag, 16);
        bad[0] ^= 0x80;
        dctx = EVP_CIPHER_CTX_new();
        if (c != NULL && dctx != NULL && EVP_DecryptInit_ex2(dctx, c, key, iv, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, bad) == 1
            && EVP_DecryptUpdate(dctx, NULL, &aadl, aad, 13) == 1
            && EVP_DecryptUpdate(dctx, back, &decl, out, outl + finl) == 1) {
            printf("%s.reject=%d\n", buf,
                   EVP_DecryptFinal_ex(dctx, back + decl, &defl) == 0);
        } else {
            printf("%s.reject=0\n", buf);
        }
        if (dctx != NULL)
            EVP_CIPHER_CTX_free(dctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The empty-plaintext and AAD-only arms, both with 13 bytes of AAD. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-OCB", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0, finl = 0, aadl = 0;

        if (c == NULL || ctx == NULL || EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) != 1
            || EVP_EncryptUpdate(ctx, NULL, &aadl, aad, 13) != 1
            || EVP_EncryptUpdate(ctx, out, &outl, in, 0) != 1
            || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("defltocb.empty=0\n");
        } else {
            printf("defltocb.empty.len=%d\n", outl + finl);
            rt_hex("defltocb.empty.tag", tag, 16);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-OCB", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0, finl = 0, aadl = 0;

        if (c == NULL || ctx == NULL || EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) != 1
            || EVP_EncryptUpdate(ctx, NULL, &aadl, aad, 20) != 1
            || EVP_EncryptFinal_ex(ctx, out, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("defltocb.aadonly=0\n");
        } else {
            printf("defltocb.aadonly.len=%d\n", finl);
            rt_hex("defltocb.aadonly.tag", tag, 16);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The IV-length window: 0 and 16 are outside 1..15; 15 is the top of it. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-OCB", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (c != NULL && ctx != NULL && EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) == 1) {
            printf("defltocb.iv0=%d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 0, NULL));
            printf("defltocb.iv16=%d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 16, NULL));
            printf("defltocb.iv15=%d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 15, NULL));
        } else {
            printf("defltocb.iv0=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The tag-length window: 16 is the maximum, 17 is refused. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-OCB", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (c != NULL && ctx != NULL && EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) == 1) {
            printf("defltocb.taglen16=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL));
            printf("defltocb.taglen17=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 17, NULL));
        } else {
            printf("defltocb.taglen16=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The provider's answer is the landed low-level answer, ciphertext and tag. */
    {
        AES_KEY ek, dk;
        OCB128_CONTEXT *octx;
        unsigned char low[80], lowtag[16];

        if (AES_set_encrypt_key(key, 128, &ek) != 0 || AES_set_decrypt_key(key, 128, &dk) != 0) {
            printf("defltocb.eq.ct=0\n");
        } else {
            EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-OCB", NULL);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outl = 0, finl = 0, aadl = 0;

            octx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt,
                                     (block128_f)AES_decrypt, NULL);
            CRYPTO_ocb128_setiv(octx, iv, sizeof(iv), 16);
            CRYPTO_ocb128_aad(octx, aad, 13);
            CRYPTO_ocb128_encrypt(octx, in, low, 33);
            CRYPTO_ocb128_tag(octx, lowtag, 16);
            CRYPTO_ocb128_cleanup(octx);

            if (c == NULL || ctx == NULL || EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) != 1
                || EVP_EncryptUpdate(ctx, NULL, &aadl, aad, 13) != 1
                || EVP_EncryptUpdate(ctx, out, &outl, in, 33) != 1
                || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1
                || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
                printf("defltocb.eq.ct=0\n");
            } else {
                printf("defltocb.eq.ct=%d\n",
                       (size_t)(outl + finl) == 33 && memcmp(out, low, 33) == 0);
                printf("defltocb.eq.tag=%d\n", memcmp(tag, lowtag, 16) == 0);
            }
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
            if (c != NULL)
                EVP_CIPHER_free(c);
        }
    }
}

/* The drained queue, normalised the one way both sides can hold: library and reason as numbers,
 * the authority's three debug strings verbatim, and the entry count. Declared here because the
 * EVP arm below uses it and `rt_errq` is defined with the dispatch arm. */
static void rt_errq(const char *tag);

/* The same refusals reached the way an application reaches them, through `EVP_*`. Four of the
 * six named paths are reachable here (the invalid key length and the too-small output buffer are
 * not, because EVP chooses those arguments), and what this arm adds is the EVP layer's own
 * contribution to the queue -- including the `EVP_R_UPDATE_ERROR` a wrap row's oversized `outl`
 * produces when EVP checks the length it was handed. */
static void rt_deflt_errors(void)
{
    unsigned char key[32], iv[16], in[32], out[64];
    int outl = 0, finl = 0;
    EVP_CIPHER *c;
    EVP_CIPHER_CTX *ctx;

    memset(key, 0x11, sizeof(key));
    memset(iv, 0x22, sizeof(iv));
    memset(in, 0x33, sizeof(in));

    /* No key set. */
    c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    ctx = EVP_CIPHER_CTX_new();
    ERR_clear_error();
    printf("evp.nokey.init=%d\n", EVP_EncryptInit_ex(ctx, c, NULL, NULL, NULL));
    printf("evp.nokey.update=%d\n", EVP_EncryptUpdate(ctx, out, &outl, in, 16));
    rt_errq("evp_nokey");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);

    /* A failed decrypt: one block of padding that does not verify. */
    c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    ctx = EVP_CIPHER_CTX_new();
    ERR_clear_error();
    printf("evp.badpad.init=%d\n", EVP_DecryptInit_ex(ctx, c, NULL, key, iv));
    outl = 0;
    printf("evp.badpad.update=%d\n", EVP_DecryptUpdate(ctx, out, &outl, in, 16));
    finl = 0;
    printf("evp.badpad.final=%d\n", EVP_DecryptFinal_ex(ctx, out + outl, &finl));
    rt_errq("evp_badpad");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);

    /* XTS with both halves of the key equal. */
    c = EVP_CIPHER_fetch(NULL, "AES-128-XTS", NULL);
    ctx = EVP_CIPHER_CTX_new();
    ERR_clear_error();
    printf("evp.xtsdup.init=%d\n", EVP_EncryptInit_ex(ctx, c, NULL, key, iv));
    rt_errq("evp_xtsdup");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);

    /* XTS with eight bytes of input. */
    memset(key, 0x44, 16);
    memset(key + 16, 0x55, 16);
    c = EVP_CIPHER_fetch(NULL, "AES-128-XTS", NULL);
    ctx = EVP_CIPHER_CTX_new();
    ERR_clear_error();
    printf("evp.xtsshort.init=%d\n", EVP_EncryptInit_ex(ctx, c, NULL, key, iv));
    outl = 0;
    printf("evp.xtsshort.update=%d\n", EVP_EncryptUpdate(ctx, out, &outl, in, 8));
    rt_errq("evp_xtsshort");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

/* ------------------------------------------------------------------------------------------
 * The provider-dispatch failure arm (`ERROR_PASS`)
 * ------------------------------------------------------------------------------------------
 *
 * `docs/PARITY_MODEL.md` §3.5 makes the `ERR` queue part of the contract: library, reason,
 * ordering and count. The authority's provider cipher rows answer most refusals by raising a
 * `PROV_R_*` error *and* returning 0, and two of the review's named paths -- an invalid key
 * length and an output buffer that is too small -- are not reachable through `EVP_EncryptInit_ex`
 * at all: the EVP layer derives the key length from the fetched cipher and the provider's
 * `outsize` from `inl + blocksize`. So this arm drives the provider's own `OSSL_DISPATCH`
 * through `OSSL_PROVIDER_query_operation`, which is the surface those errors actually belong to,
 * and lets the probe choose every argument.
 *
 * Every observation is a return code, an output length, or a drained queue entry spelled
 * `<lib>:<reason>:<file>:<line>:<func>` -- all of which the authority's own records carry. The
 * queue is cleared before each scenario so the transcript is the scenario's own errors, and the
 * count is printed as well, so a side that raises nothing is a difference rather than a silence.
 */

static const OSSL_DISPATCH *rt_disp(const OSSL_ALGORITHM *algs, const char *name)
{
    for (; algs != NULL && algs->algorithm_names != NULL; algs++) {
        const char *s = algs->algorithm_names;
        size_t n = strlen(name);

        while (*s != '\0') {
            const char *e = strchr(s, ':');
            size_t len = e == NULL ? strlen(s) : (size_t)(e - s);

            if (len == n && strncmp(s, name, n) == 0)
                return algs->implementation;
            if (e == NULL)
                break;
            s = e + 1;
        }
    }
    return NULL;
}

static void *rt_fn(const OSSL_DISPATCH *d, int id)
{
    for (; d != NULL && d->function_id != 0; d++)
        if (d->function_id == id)
            return d->function;
    return NULL;
}

/* The drained queue, normalised the one way both sides can hold: library and reason as
 * numbers, the authority's three debug strings verbatim, and the entry count. `ERR_get_error_all`
 * is the reader `ERR_print_errors` uses, so nothing here is a private accessor. */
static void rt_errq(const char *tag)
{
    unsigned long e;
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0;
    int n = 0;

    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        printf("q.%s.%d=lib%d:reason%d:%s:%d:%s\n", tag, n, ERR_GET_LIB(e),
               ERR_GET_REASON(e), file != NULL ? file : "", line,
               func != NULL ? func : "");
        n++;
    }
    printf("q.%s.count=%d\n", tag, n);
}

typedef void *(*rt_newctx_fn)(void *);
typedef int (*rt_init_fn)(void *, const unsigned char *, size_t, const unsigned char *,
                          size_t, const OSSL_PARAM *);
typedef int (*rt_update_fn)(void *, unsigned char *, size_t *, size_t,
                            const unsigned char *, size_t);
typedef int (*rt_final_fn)(void *, unsigned char *, size_t *, size_t);
typedef int (*rt_getparams_fn)(OSSL_PARAM *);
typedef void (*rt_free_fn)(void *);

static void rt_disp_failures(void)
{
    OSSL_PROVIDER *prov;
    const OSSL_ALGORITHM *algs;
    const OSSL_DISPATCH *d;
    void *pctx;
    void *ctx;
    unsigned char key[32], iv[16], in[48], out[96];
    size_t outl;
    int r;
    rt_newctx_fn newctx;
    rt_init_fn einit, dinit;
    rt_update_fn update;
    rt_final_fn final;
    rt_free_fn freectx;
    int nocache = 0;

    memset(key, 0x11, sizeof(key));
    memset(iv, 0x22, sizeof(iv));
    memset(in, 0x33, sizeof(in));

    prov = OSSL_PROVIDER_load(NULL, "default");
    printf("disp.provider=%d\n", prov != NULL);
    if (prov == NULL)
        return;
    algs = OSSL_PROVIDER_query_operation(prov, OSSL_OP_CIPHER, &nocache);
    printf("disp.algorithms=%d\n", algs != NULL);
    pctx = OSSL_PROVIDER_get0_provider_ctx(prov);

    /* ---- AES-128-CBC: the four reachable generic-engine refusals ---- */
    d = rt_disp(algs, "AES-128-CBC");
    printf("disp.cbc=%d\n", d != NULL);
    newctx = (rt_newctx_fn)rt_fn(d, OSSL_FUNC_CIPHER_NEWCTX);
    einit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_ENCRYPT_INIT);
    dinit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_DECRYPT_INIT);
    update = (rt_update_fn)rt_fn(d, OSSL_FUNC_CIPHER_UPDATE);
    final = (rt_final_fn)rt_fn(d, OSSL_FUNC_CIPHER_FINAL);
    freectx = (rt_free_fn)rt_fn(d, OSSL_FUNC_CIPHER_FREECTX);

    /* An invalid key length: 17 bytes for a 16-byte row. EVP derives the length from the
     * cipher and so cannot reach this; the provider's einit can. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 17, iv, 16, NULL);
    printf("disp.badkeylen.ret=%d\n", r);
    rt_errq("badkeylen");
    freectx(ctx);

    /* No key set: init without a key, then update. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, NULL, 0, NULL, 0, NULL);
    printf("disp.nokey.init=%d\n", r);
    outl = 0;
    r = update(ctx, out, &outl, sizeof(out), in, 32);
    printf("disp.nokey.update=%d\n", r);
    rt_errq("nokey");
    freectx(ctx);

    /* An output buffer that is too small: 8 bytes of room for 32 bytes of input. EVP always
     * offers `inl + blocksize`, so this too is dispatch-only. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 16, iv, 16, NULL);
    printf("disp.outsmall.init=%d\n", r);
    outl = 0;
    r = update(ctx, out, &outl, 8, in, 32);
    printf("disp.outsmall.ret=%d\n", r);
    rt_errq("outsmall");
    freectx(ctx);

    /* Bad padding: decrypt one block of zeros and finalise. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = dinit(ctx, key, 16, iv, 16, NULL);
    printf("disp.badpad.init=%d\n", r);
    outl = 0;
    r = update(ctx, out, &outl, sizeof(out), in, 16);
    printf("disp.badpad.update=%d\n", r);
    outl = 0;
    r = final(ctx, out, &outl, sizeof(out));
    printf("disp.badpad.final=%d\n", r);
    rt_errq("badpad");
    freectx(ctx);

    /* ---- AES-128-XTS ---- */
    memset(key, 0x11, sizeof(key));
    d = rt_disp(algs, "AES-128-XTS");
    printf("disp.xts=%d\n", d != NULL);
    newctx = (rt_newctx_fn)rt_fn(d, OSSL_FUNC_CIPHER_NEWCTX);
    einit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_ENCRYPT_INIT);
    update = (rt_update_fn)rt_fn(d, OSSL_FUNC_CIPHER_UPDATE);
    freectx = (rt_free_fn)rt_fn(d, OSSL_FUNC_CIPHER_FREECTX);

    /* Duplicated keys: both halves of the 32-byte XTS key are equal. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 32, iv, 16, NULL);
    printf("disp.xtsdup.ret=%d\n", r);
    rt_errq("xtsdup");
    freectx(ctx);

    /* A short input: 8 bytes, below the AES block size. The row's `aes_xts_cipher` returns 0
     * without raising and the row's stream update turns that into CIPHER_OPERATION_FAILED. */
    memset(key, 0x44, 16);
    memset(key + 16, 0x55, 16);
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 32, iv, 16, NULL);
    printf("disp.xtsshort.init=%d\n", r);
    outl = 0;
    r = update(ctx, out, &outl, sizeof(out), in, 8);
    printf("disp.xtsshort.update=%d\n", r);
    rt_errq("xtsshort");
    freectx(ctx);

    /* The XTS stream update's own outsize check, which EVP also cannot reach. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 32, iv, 16, NULL);
    outl = 0;
    r = update(ctx, out, &outl, 8, in, 32);
    printf("disp.xtssmall.update=%d\n", r);
    rt_errq("xtssmall");
    freectx(ctx);

    /* ---- AES-128-OCB ---- */
    d = rt_disp(algs, "AES-128-OCB");
    printf("disp.ocb=%d\n", d != NULL);
    newctx = (rt_newctx_fn)rt_fn(d, OSSL_FUNC_CIPHER_NEWCTX);
    einit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_ENCRYPT_INIT);
    freectx = (rt_free_fn)rt_fn(d, OSSL_FUNC_CIPHER_FREECTX);
    /* An IV length outside the row's 1..15 window. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 16, iv, 16, NULL);
    printf("disp.ocbivlen.ret=%d\n", r);
    rt_errq("ocbivlen");
    freectx(ctx);

    /* ---- AES-128-WRAP ---- */
    d = rt_disp(algs, "AES-128-WRAP");
    printf("disp.wrap=%d\n", d != NULL);
    newctx = (rt_newctx_fn)rt_fn(d, OSSL_FUNC_CIPHER_NEWCTX);
    einit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_ENCRYPT_INIT);
    update = (rt_update_fn)rt_fn(d, OSSL_FUNC_CIPHER_UPDATE);
    freectx = (rt_free_fn)rt_fn(d, OSSL_FUNC_CIPHER_FREECTX);

    /* An invalid key length, checked before anything else in the row's init. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 17, iv, 8, NULL);
    printf("disp.wrapkeylen.ret=%d\n", r);
    rt_errq("wrapkeylen");
    freectx(ctx);

    /* An input length that is not a multiple of eight: the internal helper refuses and the
     * row *reports success* with an enormous `outl`, because the authority stores an
     * `int`-returning helper's `-1` in a `size_t`. Both are printed. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 16, iv, 8, NULL);
    outl = 0;
    r = update(ctx, out, &outl, sizeof(out), in, 7);
    printf("disp.wrapinlen.update=%d\n", r);
    printf("disp.wrapinlen.outl=%llu\n", (unsigned long long)outl);
    rt_errq("wrapinlen");
    freectx(ctx);

    /* An output buffer that is too small, which the row checks before the helper. */
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, key, 16, iv, 8, NULL);
    outl = 0;
    r = update(ctx, out, &outl, 4, in, 16);
    printf("disp.wrapsmall.update=%d\n", r);
    rt_errq("wrapsmall");
    freectx(ctx);

    /* ---- NULL cipher: a refusal that raises *nothing*, which the queue must also show ---- */
    d = rt_disp(algs, "NULL");
    printf("disp.null=%d\n", d != NULL);
    newctx = (rt_newctx_fn)rt_fn(d, OSSL_FUNC_CIPHER_NEWCTX);
    einit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_ENCRYPT_INIT);
    update = (rt_update_fn)rt_fn(d, OSSL_FUNC_CIPHER_UPDATE);
    freectx = (rt_free_fn)rt_fn(d, OSSL_FUNC_CIPHER_FREECTX);
    ctx = newctx(pctx);
    ERR_clear_error();
    r = einit(ctx, NULL, 0, NULL, 0, NULL);
    printf("disp.null.init=%d\n", r);
    outl = 0;
    r = update(ctx, out, &outl, 2, in, 8);
    printf("disp.nullsmall.update=%d\n", r);
    rt_errq("nullsmall");
    freectx(ctx);

    /* ---- the generated decoders' repeated-key refusal ---- */
    d = rt_disp(algs, "AES-128-ECB");
    printf("disp.ecb=%d\n", d != NULL);
    {
        rt_getparams_fn getparams = (rt_getparams_fn)rt_fn(d, OSSL_FUNC_CIPHER_GET_PARAMS);
        size_t sz = 0;
        OSSL_PARAM dup[3];

        dup[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, &sz);
        dup[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, &sz);
        dup[2] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        r = getparams(dup);
        printf("disp.dupparams.ret=%d\n", r);
        rt_errq("dupparams");
    }

    OSSL_PROVIDER_unload(prov);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    rt_modes_blocks();
    rt_modes_wrap();
    rt_gcm128();
    rt_ccm128();
    rt_xts128();
    rt_ocb128();
    rt_aes();
    rt_rc4();
    rt_des();
    rt_rc2();
    rt_bf();
    rt_cast5();
    rt_idea();
    rt_seed();
    rt_camellia();
    rt_deflt_cipher();
    rt_deflt_wrap();
    rt_deflt_cts();
    rt_deflt_xts();
    rt_deflt_ocb();
    rt_deflt_errors();
    rt_disp_failures();
    return 0;
}
