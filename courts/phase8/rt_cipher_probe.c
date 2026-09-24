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
#include <openssl/crypto.h>
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

    /*
     * `DES_random_key` (D346). The one `des.h` export whose body is the random layer: it draws
     * with `RAND_priv_bytes` and loops until the draw is not one of the sixteen weak or
     * semi-weak keys, then fixes the parity. **No draw is printed** -- the value is random on
     * both sides and could not be compared -- so every arm is a property a caller relies on and
     * a boolean is the observation. The refusal path is the weak-key rejection: `not_weak`
     * observes that the loop exited on a key the weak test refuses, and `check_parity` observes
     * the parity fix that follows it.
     */
    {
        DES_cblock r1, r2;
        int i, all_odd = 1, draw_ok;

        memset(r1, 0, sizeof(r1));
        memset(r2, 0, sizeof(r2));
        printf("des.random_key.ret1=%d\n", DES_random_key(&r1));
        printf("des.random_key.ret2=%d\n", DES_random_key(&r2));
        for (i = 0; i < 8; i++) {
            int j, bit = 0;

            for (j = 0; j < 8; j++)
                bit ^= (r1[i] >> j) & 1u;
            if (bit != 1)
                all_odd = 0;
        }
        printf("des.random_key.odd_parity=%d\n", all_odd);
        printf("des.random_key.not_weak=%d\n", DES_is_weak_key(&r1) == 0);
        printf("des.random_key.check_parity=%d\n", DES_check_key_parity(&r1));
        printf("des.random_key.two_draws_differ=%d\n", memcmp(r1, r2, sizeof(r1)) != 0);
        /* The setter that consumes a drawn key accepts it: the loop's whole purpose. */
        draw_ok = DES_set_key(&r1, &ks2);
        printf("des.random_key.set_key=%d\n", draw_ok);
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

/*
 * The default provider's AES-CCM rows. CCM differs from every other AEAD row here in that its
 * parameters are context state rather than call arguments: `L` and `M` come from the IV-length and
 * tag controls, and the message length must be fixed *before* the AAD. So the observations are:
 * each row's shape; the `ivlen` a live context reports (the provider's `15 - L`, which is 7 by
 * default and therefore *not* `EVP_CIPHER_get_iv_length`'s `ivbits`); the IV-length window from
 * both ends; the standard flow -- length, AAD, payload, tag -- for a 21-octet message with 13
 * octets of AAD, per row; the decrypt round trip and the tag rejection; the empty-message and
 * AAD-only arms; the tag-length window and the encrypt-side refusal of a supplied tag *value*;
 * the TLS-record arm with its 13-octet AAD; and finally the provider answer against the landed
 * low-level `CRYPTO_ccm128_*` over the same L, M, AAD and message. The payload is split 21 + 0
 * in one arm and 0 + 33 in another so the `len`-before-AAD ordering is exercised in both.
 */
static void rt_deflt_ccm(void)
{
    /*
     * **All seven CCM rows, not only the AES three.** The engine is `ciphercommon_ccm.c` shared by
     * every family, so the AES arms below reach it once; what ARIA and SM4 add is their own
     * `ccm_<alg>_initkey` and their own schedule, and a row that built the wrong schedule would pass
     * every AES arm. The round trip at the end of this function is therefore run for each of
     * them, and the ARIA rows' bytes are also checked against their own published corpus by
     * `CT-CIPHER`.
     */
    static const char *names[] = {
        "AES-256-CCM", "AES-192-CCM", "AES-128-CCM",
        "ARIA-256-CCM", "ARIA-192-CCM", "ARIA-128-CCM", "SM4-CCM",
    };
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char in[48];
    unsigned char aad[20];
    unsigned char out[96];
    unsigned char back[96];
    unsigned char tag[16];
    unsigned char bad[16];
    char buf[160];
    char nbuf[176];
    size_t n;

    rt_fill(key, sizeof(key), 111);
    rt_fill(iv, sizeof(iv), 112);
    rt_fill(in, sizeof(in), 113);
    rt_fill(aad, sizeof(aad), 114);

    /* Each row's shape. `blocksize` is 1 (`blkbits = 8`): CCM is a stream. */
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);

        snprintf(buf, sizeof(buf), "defltccm.%s", names[n]);
        printf("%s.fetched=%d\n", buf, c != NULL);
        if (c == NULL)
            continue;
        printf("%s.keylen=%d\n", buf, EVP_CIPHER_get_key_length(c));
        printf("%s.ivlen=%d\n", buf, EVP_CIPHER_get_iv_length(c));
        printf("%s.blocksize=%d\n", buf, EVP_CIPHER_get_block_size(c));
        EVP_CIPHER_free(c);
    }

    /* The live context's own IV length: `ossl_ccm_initctx` sets `l = 8`, so the provider answers
     * 7 while `get_params` publishes 12. Both numbers are printed, because the difference is the
     * observable and the reason every arm below sets the IV length first. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (c == NULL || ctx == NULL || EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1) {
            printf("defltccm.live=0\n");
        } else {
            printf("defltccm.live.ivlen=%d\n", EVP_CIPHER_CTX_get_iv_length(ctx));
            printf("defltccm.live.taglen=%d\n", EVP_CIPHER_CTX_get_tag_length(ctx));
            printf("defltccm.live.keylen=%d\n", EVP_CIPHER_CTX_get_key_length(ctx));
            /* The IV-length window: 7..13 octets is `L in [2, 8]`; 6 and 14 are outside. */
            printf("defltccm.live.set12=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL));
            printf("defltccm.live.ivlen12=%d\n", EVP_CIPHER_CTX_get_iv_length(ctx));
            printf("defltccm.live.setl3=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, 3, NULL));
            printf("defltccm.live.ivlen13=%d\n", EVP_CIPHER_CTX_get_iv_length(ctx));
            printf("defltccm.live.set13=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 13, NULL));
            printf("defltccm.live.set7=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL));
            printf("defltccm.live.set6=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 6, NULL));
            printf("defltccm.live.set14=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 14, NULL));
            printf("defltccm.live.set255=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 255, NULL));
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The standard flow, per row: length, AAD, payload, final, tag; then the round trip and the
     * reject with one tag bit flipped. */
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);
        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *dctx = NULL;
        int outl = 0, finl = 0, aadl = 0, decl = 0, defl = 0;

        snprintf(buf, sizeof(buf), "defltccm.%s", names[n]);
        if (c == NULL || ectx == NULL
            || EVP_EncryptInit_ex2(ectx, c, NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1
            || EVP_EncryptInit_ex2(ectx, NULL, key, iv, NULL) != 1
            || EVP_EncryptUpdate(ectx, NULL, &aadl, NULL, 21) != 1
            || EVP_EncryptUpdate(ectx, NULL, &aadl, aad, 13) != 1
            || EVP_EncryptUpdate(ectx, out, &outl, in, 21) != 1
            || EVP_EncryptFinal_ex(ectx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("%s.enc=0\n", buf);
        } else {
            printf("%s.ctlen=%d\n", buf, outl + finl);
            snprintf(nbuf, sizeof(nbuf), "%s.ct", buf);
            rt_hex(nbuf, out, (size_t)(outl + finl));
            snprintf(nbuf, sizeof(nbuf), "%s.tag", buf);
            rt_hex(nbuf, tag, 16);
        }
        if (ectx != NULL)
            EVP_CIPHER_CTX_free(ectx);

        dctx = EVP_CIPHER_CTX_new();
        if (c != NULL && dctx != NULL
            && EVP_DecryptInit_ex2(dctx, c, NULL, NULL, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1
            && EVP_DecryptInit_ex2(dctx, NULL, key, iv, NULL) == 1
            && EVP_DecryptUpdate(dctx, NULL, &aadl, NULL, 21) == 1
            && EVP_DecryptUpdate(dctx, NULL, &aadl, aad, 13) == 1
            && EVP_DecryptUpdate(dctx, back, &decl, out, 21) == 1) {
            printf("%s.accept=%d\n", buf,
                   EVP_DecryptFinal_ex(dctx, back + decl, &defl) == 1
                   && (size_t)(decl + defl) == 21 && memcmp(back, in, 21) == 0);
        } else {
            printf("%s.accept=0\n", buf);
        }
        if (dctx != NULL)
            EVP_CIPHER_CTX_free(dctx);

        memcpy(bad, tag, 16);
        bad[0] ^= 0x80;
        dctx = EVP_CIPHER_CTX_new();
        if (c != NULL && dctx != NULL
            && EVP_DecryptInit_ex2(dctx, c, NULL, NULL, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, bad) == 1
            && EVP_DecryptInit_ex2(dctx, NULL, key, iv, NULL) == 1
            && EVP_DecryptUpdate(dctx, NULL, &aadl, NULL, 21) == 1
            && EVP_DecryptUpdate(dctx, NULL, &aadl, aad, 13) == 1
            && EVP_DecryptUpdate(dctx, back, &decl, out, 21) == 1) {
            printf("%s.reject=%d\n", buf,
                   EVP_DecryptFinal_ex(dctx, back + decl, &defl) == 0);
            /* The refusal cleanses the payload the decrypt already wrote. */
            snprintf(nbuf, sizeof(nbuf), "%s.rejectbuf", buf);
            rt_hex(nbuf, back, 21);
        } else {
            printf("%s.reject=0\n", buf);
        }
        if (dctx != NULL)
            EVP_CIPHER_CTX_free(dctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The empty message with AAD only, and a 33-octet message with no AAD at all. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0, finl = 0, aadl = 0;

        if (c == NULL || ctx == NULL
            || EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1
            || EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL) != 1
            || EVP_EncryptUpdate(ctx, NULL, &aadl, NULL, 0) != 1
            || EVP_EncryptUpdate(ctx, NULL, &aadl, aad, 13) != 1
            || EVP_EncryptUpdate(ctx, out, &outl, in, 0) != 1
            || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("defltccm.empty=0\n");
        } else {
            printf("defltccm.empty.len=%d\n", outl + finl);
            rt_hex("defltccm.empty.tag", tag, 16);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0, finl = 0, aadl = 0;

        if (c == NULL || ctx == NULL
            || EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1
            || EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL) != 1
            || EVP_EncryptUpdate(ctx, NULL, &aadl, NULL, 33) != 1
            || EVP_EncryptUpdate(ctx, out, &outl, in, 33) != 1
            || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("defltccm.noaad=0\n");
        } else {
            printf("defltccm.noaad.len=%d\n", outl + finl);
            rt_hex("defltccm.noaad.ct", out, 33);
            rt_hex("defltccm.noaad.tag", tag, 16);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The tag-length window -- even and in 4..16 -- and the encrypt-side refusal of a tag
     * *value* (the tag is an output there, so only a NULL data pointer is a length). */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (c != NULL && ctx != NULL && EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) == 1) {
            printf("defltccm.tl.4=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 4, NULL));
            printf("defltccm.tl.16=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL));
            printf("defltccm.tl.2=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 2, NULL));
            printf("defltccm.tl.3=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 3, NULL));
            printf("defltccm.tl.18=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 18, NULL));
            printf("defltccm.tl.value=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag));
            printf("defltccm.tl.taglen=%d\n", EVP_CIPHER_CTX_get_tag_length(ctx));
        } else {
            printf("defltccm.tl.4=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The TLS-record arm: 13 octets of AAD whose last two octets carry the length, then one
     * in-place record of 8 explicit-IV octets, 21 payload octets and the 16-octet tag. The
     * control's answer is `M`, and the payload length it encodes must be corrected by both the
     * explicit IV and (for decryption) the tag. */
    {
        unsigned char tlsaad[13];
        unsigned char rec[64];
        unsigned char rec2[64];
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0, finl = 0;

        rt_fill(tlsaad, sizeof(tlsaad), 115);
        tlsaad[11] = 0;
        tlsaad[12] = 21;
        memcpy(rec, in, 45);
        memcpy(rec2, in, 45);

        if (c == NULL || ctx == NULL
            || EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1
            || EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL) != 1) {
            printf("defltccm.tls.pad=0\n");
        } else {
            printf("defltccm.tls.pad=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 13, tlsaad));
            printf("defltccm.tls.update=%d\n",
                   EVP_EncryptUpdate(ctx, rec, &outl, rec, 45));
            printf("defltccm.tls.outl=%d\n", outl);
            rt_hex("defltccm.tls.rec", rec, 45);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);

        /* A record shorter than the explicit IV plus the tag is refused in place. */
        c = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
        ctx = EVP_CIPHER_CTX_new();
        if (c == NULL || ctx == NULL
            || EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1
            || EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL) != 1) {
            printf("defltccm.tlsshort=0\n");
        } else {
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 13, tlsaad);
            outl = 0;
            printf("defltccm.tlsshort.update=%d\n",
                   EVP_EncryptUpdate(ctx, rec2, &outl, rec2, 23));
            printf("defltccm.tlsshort.outl=%d\n", outl);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The provider's answer is the landed low-level answer: same L (12-octet nonce), same M,
     * same 13-octet AAD, same 21-octet message. */
    {
        AES_KEY aeskey;
        rt_ccm_ctx c1;
        CCM128_CONTEXT *low;
        unsigned char lowct[64], lowtag[16];

        if (AES_set_encrypt_key(key, 128, &aeskey) != 0) {
            printf("defltccm.eq.ct=0\n");
        } else {
            EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outl = 0, finl = 0, aadl = 0;

            memset(&c1, 0, sizeof(c1));
            low = (CCM128_CONTEXT *)&c1;
            CRYPTO_ccm128_init(low, 16, 3, &aeskey, (block128_f)AES_encrypt);
            CRYPTO_ccm128_setiv(low, iv, 12, 21);
            CRYPTO_ccm128_aad(low, aad, 13);
            CRYPTO_ccm128_encrypt(low, in, lowct, 21);
            CRYPTO_ccm128_tag(low, lowtag, 16);

            if (c == NULL || ctx == NULL
                || EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1
                || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1
                || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1
                || EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL) != 1
                || EVP_EncryptUpdate(ctx, NULL, &aadl, NULL, 21) != 1
                || EVP_EncryptUpdate(ctx, NULL, &aadl, aad, 13) != 1
                || EVP_EncryptUpdate(ctx, out, &outl, in, 21) != 1
                || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1
                || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
                printf("defltccm.eq.ct=0\n");
            } else {
                printf("defltccm.eq.ct=%d\n",
                       (size_t)(outl + finl) == 21 && memcmp(out, lowct, 21) == 0);
                printf("defltccm.eq.tag=%d\n", memcmp(tag, lowtag, 16) == 0);
            }
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
            if (c != NULL)
                EVP_CIPHER_free(c);
        }
    }

    /*
     * The per-row CCM round trip over **every** family, not only the AES three. What ARIA and SM4
     * add to the shared `ciphercommon_ccm.c` engine is their own `ccm_<alg>_initkey` and their own
     * schedule, and a row that built the wrong schedule would pass every AES arm above. The
     * 48-octet payload is deliberately not a multiple of 16, so the partial-block path is reached,
     * and a one-bit flip in the tag must be refused by the final.
     */
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);
        EVP_CIPHER_CTX *e, *d;
        int outl = 0, finl = 0, aadl = 0, backl = 0;
        size_t clen;

        snprintf(buf, sizeof(buf), "defltccmrt.%s", names[n]);
        if (c == NULL) {
            printf("%s.ok=0\n", buf);
            continue;
        }
        clen = (size_t)EVP_CIPHER_get_key_length(c);
        e = EVP_CIPHER_CTX_new();
        d = EVP_CIPHER_CTX_new();
        if (e == NULL || d == NULL
            || EVP_EncryptInit_ex2(e, c, NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_AEAD_SET_TAG, 16, NULL) != 1
            || EVP_EncryptInit_ex2(e, NULL, key, iv, NULL) != 1
            || EVP_EncryptUpdate(e, NULL, &aadl, NULL, (int)sizeof(in)) != 1
            || EVP_EncryptUpdate(e, NULL, &aadl, aad, (int)sizeof(aad)) != 1
            || EVP_EncryptUpdate(e, out, &outl, in, (int)sizeof(in)) != 1
            || EVP_EncryptFinal_ex(e, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("%s.ok=0\n", buf);
        } else {
            printf("%s.ct.len=%d\n", buf, outl + finl);
            printf("%s.ct.is_not_plaintext=%d\n", buf, memcmp(out, in, sizeof(in)) != 0);
            if (EVP_DecryptInit_ex2(d, c, NULL, NULL, NULL) != 1
                || EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1
                || EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1
                || EVP_DecryptInit_ex2(d, NULL, key, iv, NULL) != 1
                || EVP_DecryptUpdate(d, NULL, &aadl, NULL, (int)sizeof(in)) != 1
                || EVP_DecryptUpdate(d, NULL, &aadl, aad, (int)sizeof(aad)) != 1
                || EVP_DecryptUpdate(d, back, &backl, out, outl + finl) != 1
                || EVP_DecryptFinal_ex(d, back + backl, &finl) != 1) {
                printf("%s.rt=0\n", buf);
            } else {
                printf("%s.rt=%d\n", buf,
                       backl + finl == (int)sizeof(in) && memcmp(back, in, sizeof(in)) == 0);
            }
            /*
             * A one-bit flip in the tag must be refused by the final. **Every step's return value is
             * printed**, because the first version of this arm reported only whether the whole chain
             * succeeded and printed `setup_refused` on the authority -- an arm that stops before the
             * call it names is the class D261 recorded, so which step refuses is the observation.
             */
            memcpy(bad, tag, sizeof(bad));
            bad[0] = (unsigned char)(bad[0] ^ 0x40);
            {
                int r1 = EVP_DecryptInit_ex2(d, c, NULL, NULL, NULL);
                int r2 = r1 == 1 ? EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) : -1;
                int r3 = r2 == 1
                             ? EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_AEAD_SET_TAG, 16, bad)
                             : -1;
                int r4 = r3 == 1 ? EVP_DecryptInit_ex2(d, NULL, key, iv, NULL) : -1;
                int r5 = r4 == 1 ? EVP_DecryptUpdate(d, NULL, &aadl, NULL, (int)sizeof(in)) : -1;
                int r6 = r5 == 1 ? EVP_DecryptUpdate(d, NULL, &aadl, aad, (int)sizeof(aad)) : -1;
                int r7 = r6 == 1
                             ? EVP_DecryptUpdate(d, back, &backl, out, outl + finl)
                             : -1;
                int rf = r7 == 1 ? EVP_DecryptFinal_ex(d, back + backl, &finl) : -1;

                printf("%s.badtag.steps=%d,%d,%d,%d,%d,%d,%d,%d\n", buf, r1, r2, r3, r4, r5, r6,
                       r7, rf);
            }
        }
        printf("%s.keylen=%zu\n", buf, clen);
        if (e != NULL)
            EVP_CIPHER_CTX_free(e);
        if (d != NULL)
            EVP_CIPHER_CTX_free(d);
        EVP_CIPHER_free(c);
    }
}

/*
 * The default provider's AES-SIV rows. SIV's flow is the mirror image of every other AEAD here:
 * there is no IV at all (`ivbits` is 0 and `siv_init` ignores whatever a caller passes), the
 * AAD **is** the nonce per RFC 5297 and is fed as ordinary associated data, the tag is the
 * synthetic IV and is produced by the payload update rather than by the final, and `Final` is
 * what reports whether the operation succeeded. So the observations are: each row's shape;
 * RFC 5297 Appendix A.1's own vector, which is an *independent* published expectation rather
 * than a mirror of the authority; the two-piece AAD of that vector; the decrypt round trip; the
 * tag rejection; an AAD-only operation; the tag-length refusal in both directions; and the
 * `speed` parameter, which is the one knob that lifts S2V's single-operation limit.
 */
static void rt_deflt_siv(void)
{
    static const char *names[] = { "AES-256-SIV", "AES-192-SIV", "AES-128-SIV" };
    /* RFC 5297 Appendix A.1, verbatim: the K1 || K2 key, the 24-octet associated data, the
     * plaintext, the SIV and the ciphertext. The AD is **one** component, not two: the RFC
     * prints it wrapped over two lines for width, and OpenSSL's own
     * `test/recipes/30-test_evp_data/evpciph_aes_siv.txt` carries it as a single `AAD =` line.
     * S2V is `D = dbl(D) xor CMAC(S_i)` per component, so feeding AD1||AD2 as two update calls
     * would be a *different* SIV input -- which is exactly the mistake this comment records. */
    static const unsigned char rkey[32] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    static const unsigned char rad[24] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };
    static const unsigned char rpt[14] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
    };
    static const unsigned char rsiv[16] = {
        0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
        0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93
    };
    static const unsigned char rct[14] = {
        0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
        0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c
    };
    unsigned char key[64];
    unsigned char in[48];
    unsigned char aad[20];
    unsigned char out[96];
    unsigned char back[96];
    unsigned char tag[16];
    unsigned char bad[16];
    char buf[160];
    char nbuf[176];
    size_t n;

    rt_fill(key, sizeof(key), 121);
    rt_fill(in, sizeof(in), 122);
    rt_fill(aad, sizeof(aad), 123);

    /* Each row's shape: the key is *twice* the algorithm's, and the IV length is zero. */
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);

        snprintf(buf, sizeof(buf), "defltsiv.%s", names[n]);
        printf("%s.fetched=%d\n", buf, c != NULL);
        if (c == NULL)
            continue;
        printf("%s.keylen=%d\n", buf, EVP_CIPHER_get_key_length(c));
        printf("%s.ivlen=%d\n", buf, EVP_CIPHER_get_iv_length(c));
        printf("%s.blocksize=%d\n", buf, EVP_CIPHER_get_block_size(c));
        printf("%s.mode=%d\n", buf, EVP_CIPHER_get_mode(c));
        EVP_CIPHER_free(c);
    }

    /* RFC 5297 Appendix A.1 through AES-128-SIV, which is the row that vector's 32-octet key
     * belongs to. The published SIV and ciphertext are compared to what the provider produces,
     * so this arm is a known-answer test *and* a parity observation. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0, finl = 0, aadl = 0;

        if (c == NULL || ctx == NULL
            || EVP_EncryptInit_ex2(ctx, c, rkey, NULL, NULL) != 1
            || EVP_EncryptUpdate(ctx, NULL, &aadl, rad, (int)sizeof(rad)) != 1
            || EVP_EncryptUpdate(ctx, out, &outl, rpt, (int)sizeof(rpt)) != 1
            || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("defltsiv.rfc.enc=0\n");
        } else {
            printf("defltsiv.rfc.ctlen=%d\n", outl + finl);
            printf("defltsiv.rfc.ct=%d\n",
                   (size_t)(outl + finl) == sizeof(rct) && memcmp(out, rct, sizeof(rct)) == 0);
            printf("defltsiv.rfc.siv=%d\n", memcmp(tag, rsiv, 16) == 0);
            rt_hex("defltsiv.rfc.ctv", out, (size_t)(outl + finl));
            rt_hex("defltsiv.rfc.sivv", tag, 16);
            printf("defltsiv.rfc.taglen=%d\n", EVP_CIPHER_CTX_get_tag_length(ctx));
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);

        /* The round trip, under the *published* SIV rather than the produced one. */
        ctx = EVP_CIPHER_CTX_new();
        if (c != NULL && ctx != NULL
            && EVP_DecryptInit_ex2(ctx, c, rkey, NULL, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)rsiv) == 1
            && EVP_DecryptUpdate(ctx, NULL, &aadl, rad, (int)sizeof(rad)) == 1
            && EVP_DecryptUpdate(ctx, back, &outl, rct, (int)sizeof(rct)) == 1) {
            printf("defltsiv.rfc.accept=%d\n",
                   EVP_DecryptFinal_ex(ctx, back + outl, &finl) == 1
                   && (size_t)(outl + finl) == sizeof(rpt)
                   && memcmp(back, rpt, sizeof(rpt)) == 0);
        } else {
            printf("defltsiv.rfc.accept=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);

        /* One SIV bit flipped: the refusal, and the cleansed output behind it. */
        memcpy(bad, rsiv, 16);
        bad[0] ^= 0x80;
        ctx = EVP_CIPHER_CTX_new();
        if (c != NULL && ctx != NULL
            && EVP_DecryptInit_ex2(ctx, c, rkey, NULL, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, bad) == 1
            && EVP_DecryptUpdate(ctx, NULL, &aadl, rad, (int)sizeof(rad)) == 1
            && EVP_DecryptUpdate(ctx, back, &outl, rct, (int)sizeof(rct)) == 1) {
            printf("defltsiv.rfc.reject=%d\n",
                   EVP_DecryptFinal_ex(ctx, back + outl, &finl) == 0);
            rt_hex("defltsiv.rfc.rejectbuf", back, sizeof(rct));
        } else {
            printf("defltsiv.rfc.reject=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The round trip over each row's own key length, with one AAD piece and a 48-octet
     * message, so every row's fetched CBC/CTR pair is exercised. */
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);
        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *dctx = NULL;
        int outl = 0, finl = 0, aadl = 0, decl = 0, defl = 0;

        snprintf(buf, sizeof(buf), "defltsiv.%s", names[n]);
        if (c == NULL || ectx == NULL
            || EVP_EncryptInit_ex2(ectx, c, key, NULL, NULL) != 1
            || EVP_EncryptUpdate(ectx, NULL, &aadl, aad, 13) != 1
            || EVP_EncryptUpdate(ectx, out, &outl, in, 48) != 1
            || EVP_EncryptFinal_ex(ectx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("%s.enc=0\n", buf);
        } else {
            printf("%s.ctlen=%d\n", buf, outl + finl);
            snprintf(nbuf, sizeof(nbuf), "%s.ct", buf);
            rt_hex(nbuf, out, (size_t)(outl + finl));
            snprintf(nbuf, sizeof(nbuf), "%s.tag", buf);
            rt_hex(nbuf, tag, 16);
        }
        if (ectx != NULL)
            EVP_CIPHER_CTX_free(ectx);

        dctx = EVP_CIPHER_CTX_new();
        if (c != NULL && dctx != NULL
            && EVP_DecryptInit_ex2(dctx, c, key, NULL, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1
            && EVP_DecryptUpdate(dctx, NULL, &aadl, aad, 13) == 1
            && EVP_DecryptUpdate(dctx, back, &decl, out, 48) == 1) {
            printf("%s.accept=%d\n", buf,
                   EVP_DecryptFinal_ex(dctx, back + decl, &defl) == 1
                   && (size_t)(decl + defl) == 48 && memcmp(back, in, 48) == 0);
        } else {
            printf("%s.accept=0\n", buf);
        }
        if (dctx != NULL)
            EVP_CIPHER_CTX_free(dctx);

        /* The key length is the row's own; the wrong one is refused. EVP derives it from the
         * cipher, so that refusal is the dispatch arm's, not this one's. */
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* An AAD-only operation: the tag is S2V over the AAD alone, and the payload is empty. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0, finl = 0, aadl = 0;

        if (c == NULL || ctx == NULL
            || EVP_EncryptInit_ex2(ctx, c, rkey, NULL, NULL) != 1
            || EVP_EncryptUpdate(ctx, NULL, &aadl, rad, 16) != 1
            || EVP_EncryptUpdate(ctx, out, &outl, in, 0) != 1
            || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("defltsiv.aadonly=0\n");
        } else {
            printf("defltsiv.aadonly.len=%d\n", outl + finl);
            rt_hex("defltsiv.aadonly.tag", tag, 16);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The tag-length window: `ossl_siv128_set_tag` and `get_tag` accept only 16, and the
     * getter refuses an encryption context that has not produced one. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (c != NULL && ctx != NULL && EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) == 1) {
            printf("defltsiv.tl.get=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
            printf("defltsiv.tl.get15=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 15, tag));
            printf("defltsiv.tl.set=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag));
            printf("defltsiv.tl.set15=%d\n",
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 15, tag));
        } else {
            printf("defltsiv.tl.get=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* `speed` is the only settable besides the tag and the key length; setting it must not
     * disturb the operation. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0, finl = 0, aadl = 0;

        if (c == NULL || ctx == NULL
            || EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_SPEED, 1, NULL) != 1
            || EVP_EncryptInit_ex2(ctx, NULL, rkey, NULL, NULL) != 1
            || EVP_EncryptUpdate(ctx, NULL, &aadl, rad, 24) != 1
            || EVP_EncryptUpdate(ctx, out, &outl, rpt, 14) != 1
            || EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            printf("defltsiv.speed.enc=0\n");
        } else {
            printf("defltsiv.speed.same=%d\n", memcmp(tag, rsiv, 16) == 0);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (c != NULL)
            EVP_CIPHER_free(c);
    }

    /* The provider context's library context (`PROV_LIBCTX_OF`), the observation D240 named and
     * D241's plumbing exists to make true. A private `OSSL_LIB_CTX` is created, the default
     * provider is loaded **in it**, and AES-128-SIV is fetched and run there; the same operation
     * is run in the global context and the two tags are compared to each other and to the
     * published RFC 5297 A.1 value.
     *
     * SIV is the one landed row that makes this observable at all. `aes_siv_initkey` and
     * `ossl_siv128_init` both sub-fetch their CBC/CTR pair through `PROV_LIBCTX_OF(provctx)`, so
     * a NULL `provctx` -- or a NULL `ctx->libctx` -- would resolve those sub-fetches in the
     * *global* library context instead of the private one. The tag would still be correct, which
     * is exactly why this arm is written as a three-way observation rather than as a KAT: the
     * `same` line is the one that would move first if the context stopped being carried. */
    {
        OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *lp = NULL;
        EVP_CIPHER *gc = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
        EVP_CIPHER *pc = NULL;
        unsigned char gtag[16];
        unsigned char ptag[16];
        int gok = 0;
        int pok = 0;

        memset(gtag, 0, sizeof(gtag));
        memset(ptag, 0, sizeof(ptag));

        printf("defltsiv.libctx.new=%d\n", lc != NULL);
        if (lc != NULL) {
            lp = OSSL_PROVIDER_load(lc, "default");
            printf("defltsiv.libctx.load=%d\n", lp != NULL);
            pc = EVP_CIPHER_fetch(lc, "AES-128-SIV", NULL);
        }
        printf("defltsiv.libctx.fetch=%d\n", pc != NULL);

        if (gc != NULL) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outl = 0, finl = 0, aadl = 0;

            if (ctx != NULL
                && EVP_EncryptInit_ex2(ctx, gc, rkey, NULL, NULL) == 1
                && EVP_EncryptUpdate(ctx, NULL, &aadl, rad, (int)sizeof(rad)) == 1
                && EVP_EncryptUpdate(ctx, out, &outl, rpt, (int)sizeof(rpt)) == 1
                && EVP_EncryptFinal_ex(ctx, out + outl, &finl) == 1
                && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, gtag) == 1)
                gok = 1;
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
        }
        if (pc != NULL) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outl = 0, finl = 0, aadl = 0;

            if (ctx != NULL
                && EVP_EncryptInit_ex2(ctx, pc, rkey, NULL, NULL) == 1
                && EVP_EncryptUpdate(ctx, NULL, &aadl, rad, (int)sizeof(rad)) == 1
                && EVP_EncryptUpdate(ctx, out, &outl, rpt, (int)sizeof(rpt)) == 1
                && EVP_EncryptFinal_ex(ctx, out + outl, &finl) == 1
                && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ptag) == 1)
                pok = 1;
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
        }

        printf("defltsiv.libctx.globalkat=%d\n", gok && memcmp(gtag, rsiv, 16) == 0);
        printf("defltsiv.libctx.privatekat=%d\n", pok && memcmp(ptag, rsiv, 16) == 0);
        printf("defltsiv.libctx.same=%d\n", gok && pok && memcmp(gtag, ptag, 16) == 0);
        rt_hex("defltsiv.libctx.privatesiv", ptag, 16);

        /* The three lines above prove the private context *works*; they cannot prove the row's
         * sub-fetches are *scoped* to it, because the global context can always answer them. This
         * block makes scoping observable: default properties are a per-`OSSL_LIB_CTX` preference,
         * and `ossl_siv128_init` reaches CMAC through `EVP_MAC_fetch(libctx, "CMAC", NULL)` with a
         * NULL property query -- so the *default* properties of whichever context it was handed
         * decide whether that fetch resolves. Setting `fips=yes` on the private context only must
         * therefore break the private run and leave the global one alone. */
        {
            EVP_MAC *m = EVP_MAC_fetch(lc, "CMAC", NULL);
            int pinit = -1;

            printf("defltsiv.libctx.macbefore=%d\n", m != NULL);
            EVP_MAC_free(m);
            printf("defltsiv.libctx.setprops=%d\n",
                   lc != NULL && EVP_set_default_properties(lc, "fips=yes") == 1);
            m = EVP_MAC_fetch(lc, "CMAC", NULL);
            printf("defltsiv.libctx.macafter=%d\n", m != NULL);
            EVP_MAC_free(m);
            m = EVP_MAC_fetch(NULL, "CMAC", NULL);
            printf("defltsiv.libctx.macglobal=%d\n", m != NULL);
            EVP_MAC_free(m);

            if (pc != NULL) {
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

                if (ctx != NULL)
                    pinit = EVP_EncryptInit_ex2(ctx, pc, rkey, NULL, NULL);
                printf("defltsiv.libctx.propsinit=%d\n", pinit);
                if (ctx != NULL)
                    EVP_CIPHER_CTX_free(ctx);
            }
        }

        if (pc != NULL)
            EVP_CIPHER_free(pc);
        if (gc != NULL)
            EVP_CIPHER_free(gc);
        if (lp != NULL)
            OSSL_PROVIDER_unload(lp);
        if (lc != NULL)
            OSSL_LIB_CTX_free(lc);
    }
}

/*
 * Every cipher row the census records as implemented, fetched by name and measured the way
 * `EVP_CIPHER_get_*` answers. This arm exists because of a measured coverage gap: 39 of the 82
 * implemented `OSSL_OP_CIPHER` rows were named nowhere in any probe, so the census could call them
 * `implemented` while no observation touched them at all. The list is checked against
 * `forensics/atlas/provider-algorithms.json` by `forensics/tools/provider_court_coverage.py`, so it
 * cannot go stale in either direction: a row landed without a line here, and a line here for a row
 * the census does not call implemented, are both failures.
 *
 * The five observations per row are deliberately not just `fetched`: key length, IV length, block
 * size and mode are what `EVP_CIPHER_get_*` answers, and a row whose engine is right but whose
 * descriptor is wrong would pass a fetch-only arm.
 */
/*
 * Print a published `OSSL_PARAM` list in full: the key, the type and the *size*, in order, with a
 * count. The size is the third field on purpose. `OSSL_PARAM_size_t` and `OSSL_PARAM_uint` both
 * carry `OSSL_PARAM_UNSIGNED_INTEGER` and differ only in `data_size` (8 and 4), and a caller reads
 * that field; a list transcribed with the type right and the size zero is wrong in a way a
 * keys-only comparison cannot see. `tag` is the observation family, `noun` the row's own name.
 */
static void rt_param_list(const char *tag, const char *noun, const char *kind,
                          const OSSL_PARAM *p)
{
    size_t n = 0;

    printf("%s.%s.%s.present=%d\n", tag, noun, kind, p != NULL);
    for (; p != NULL && p->key != NULL; p++, n++)
        printf("%s.%s.%s.%zu=%s:%u:%zu\n", tag, noun, kind, n, p->key, p->data_type,
               p->data_size);
    printf("%s.%s.%s.count=%zu\n", tag, noun, kind, n);
}


/*
 * The four published `AES-*-CBC-HMAC-*` rows -- `cipher_aes_cbc_hmac_sha.c` with
 * `cipher_aes_cbc_hmac_sha1_hw.c` and `cipher_aes_cbc_hmac_sha256_hw.c`.
 *
 * Nine more rows of the same family sit in `deflt_ciphers[]` and are dropped on this host by
 * their own capability predicates; the census arm above observes them as `fetched=0`. The four
 * here are the ones whose predicate is the AES-NI bit, so they are published and their whole
 * record construction is observable.
 *
 * What it observes, per row
 * -------------------------
 *   * the published flags, which carry `EVP_CIPH_FLAG_AEAD_CIPHER` and
 *     `EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK` and are how a caller learns the row is stitched at all;
 *   * every key of the row's own settable list, set through `EVP_CIPHER_CTX_set_params`, so
 *     `aes_set_ctx_params`'s arms and their coordinates are reached rather than only its
 *     signature;
 *   * every key of its gettable list, read the same way -- including the two values that no other
 *     row has, `tls1multi_maxbufsz` and `tls1multi_aadpacklen`;
 *   * a whole TLS 1.0 record: the ciphertext, the decrypting side's acceptance and the plaintext
 *     it returns, and a refusal when one ciphertext byte is flipped.
 *
 * **TLS 1.0 (`0x0301`) is the version chosen on purpose**: it is the one with no explicit IV, so
 * the record is a pure function of the key, the MAC key, the IV and the payload and a diff is a
 * defect rather than a random draw. The TLS 1.1+ surface is reached through the multiblock AAD
 * parameter, which is size arithmetic and therefore deterministic too. The multiblock *encrypt*
 * parameter is deliberately absent: on the authority it draws its per-record IVs from
 * `RAND_bytes_ex`, and `crypto/rand/` is Phase 9's -- the row's one recorded narrowing, named in
 * `docs/SECURITY_DIVERGENCE_POLICY.md` §4 rather than left to be discovered by its absence here.
 */
static void rt_cbchmac_records(void)
{
    static const char *names[] = {
        "AES-128-CBC-HMAC-SHA1", "AES-256-CBC-HMAC-SHA1",
        "AES-128-CBC-HMAC-SHA256", "AES-256-CBC-HMAC-SHA256",
    };
    size_t n;

    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);
        EVP_CIPHER_CTX *ctx;
        unsigned char key[32], mackey[16], iv[16], aad[13];
        unsigned char in[64], ct[64], pt[64], mbin[13];
        int r;

        printf("cbchmac.%s.fetched=%d\n", names[n], c != NULL);
        if (c == NULL)
            continue;

        printf("cbchmac.%s.flags=%lu\n", names[n], EVP_CIPHER_get_flags(c));
        printf("cbchmac.%s.keylen=%d\n", names[n], EVP_CIPHER_get_key_length(c));
        printf("cbchmac.%s.ivlen=%d\n", names[n], EVP_CIPHER_get_iv_length(c));
        printf("cbchmac.%s.blocksize=%d\n", names[n], EVP_CIPHER_get_block_size(c));

        rt_fill(key, 32, 71u + (unsigned int)n);
        rt_fill(mackey, 16, 81u + (unsigned int)n);
        rt_fill(iv, 16, 91u + (unsigned int)n);
        rt_fill(in, 32, 101u + (unsigned int)n);
        memset(in + 32, 0, 32);

        /*
         * The thirteen-byte TLS AAD: byte 8 is the content type, 9..10 the version and 11..12 the
         * record length. For TLS 1.0 the length is the payload length, because there is no
         * explicit IV to subtract; the encrypting side rewrites bytes 11..12 for TLS 1.1 and later,
         * which is why the same buffer is handed to the decrypting side untouched below.
         */
        memset(aad, 0, sizeof(aad));
        aad[8] = 0x17;
        aad[9] = 0x03;
        aad[10] = 0x01;
        aad[11] = 0;
        aad[12] = 32;

        ctx = EVP_CIPHER_CTX_new();
        r = EVP_CipherInit_ex2(ctx, c, key, iv, 1, NULL);
        printf("cbchmac.%s.einit=%d\n", names[n], r);
        {
            /*
             * `tls1multi_maxbufsz` asserts this is non-zero before it computes
             * (`cipher_aes_cbc_hmac_sha1_hw.c:701`), and the assertion is live in the pinned
             * build: reading the buffer size before setting the fragment aborts the *authority*,
             * so the arm sets it first, in the order a real TLS caller does.
             */
            size_t frag = 16384;
            OSSL_PARAM sp[4];

            sp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mackey, 16);
            sp[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, aad, 13);
            sp[2] = OSSL_PARAM_construct_size_t(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, &frag);
            sp[3] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_set_params(ctx, sp);
            printf("cbchmac.%s.setparams=%d\n", names[n], r);
        }
        {
            size_t maxbufsz = 0, encl = 0, aadpad = 0, kl = 0, ivl = 0;
            unsigned int il = 0, pk = 0;
            unsigned char giv[16], guiv[16];
            OSSL_PARAM gp[10];

            gp[0] = OSSL_PARAM_construct_size_t(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE, &maxbufsz);
            gp[1] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, &il);
            gp[2] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN, &pk);
            gp[3] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN, &encl);
            gp[4] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, &aadpad);
            gp[5] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &kl);
            gp[6] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivl);
            gp[7] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_IV, giv, sizeof(giv));
            gp[8] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, guiv,
                                                     sizeof(guiv));
            gp[9] = OSSL_PARAM_construct_end();
            memset(giv, 0xee, sizeof(giv));
            memset(guiv, 0xee, sizeof(guiv));
            ERR_clear_error();
            r = EVP_CIPHER_CTX_get_params(ctx, gp);
            printf("cbchmac.%s.getparams=%d\n", names[n], r);
            printf("cbchmac.%s.g.maxbufsz=%zu\n", names[n], maxbufsz);
            printf("cbchmac.%s.g.interleave=%u\n", names[n], il);
            printf("cbchmac.%s.g.aadpacklen=%u\n", names[n], pk);
            printf("cbchmac.%s.g.enclen=%zu\n", names[n], encl);
            printf("cbchmac.%s.g.aadpad=%zu\n", names[n], aadpad);
            printf("cbchmac.%s.g.keylen=%zu\n", names[n], kl);
            printf("cbchmac.%s.g.ivlen=%zu\n", names[n], ivl);
            rt_hexf("cbchmac.g.iv", (int)n, giv, sizeof(giv));
            rt_hexf("cbchmac.g.uiv", (int)n, guiv, sizeof(guiv));
        }
        /*
         * The multiblock AAD parameter: the TLS 1.1+ surface, and the only part of the multiblock
         * contract that does not need the random layer. Its input is the thirteen-byte AAD and its
         * outputs are the interleave and the pack length, both read back through the getter.
         */
        {
            unsigned int il = 4;
            OSSL_PARAM mp[3];

            memset(mbin, 0, sizeof(mbin));
            mbin[8] = 0x17;
            mbin[9] = 0x03;
            mbin[10] = 0x03;
            mbin[11] = 0x20;
            mbin[12] = 0x00;
            mp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD, mbin,
                                                      sizeof(mbin));
            mp[1] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, &il);
            mp[2] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_set_params(ctx, mp);
            printf("cbchmac.%s.mbaad=%d\n", names[n], r);
            {
                unsigned int il2 = 0, pk2 = 0;
                OSSL_PARAM gp2[3];

                gp2[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE,
                                                   &il2);
                gp2[1] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN,
                                                   &pk2);
                gp2[2] = OSSL_PARAM_construct_end();
                ERR_clear_error();
                r = EVP_CIPHER_CTX_get_params(ctx, gp2);
                printf("cbchmac.%s.mbaad.get=%d il=%u pk=%u\n", names[n], r, il2, pk2);
            }
        }
        EVP_CIPHER_CTX_free(ctx);

        /*
         * The record. The input is sixty-four bytes whose first thirty-two are the payload: the
         * row's own length test is `len == ((payload + digest + block) & -block)`, which for a
         * thirty-two-byte payload and a twenty-byte digest is sixty-four, so the arm's buffer is
         * exactly one record and the cipher fills the rest with the MAC and the padding.
         */
        ctx = EVP_CIPHER_CTX_new();
        r = EVP_CipherInit_ex2(ctx, c, key, iv, 1, NULL);
        printf("cbchmac.%s.rec.einit=%d\n", names[n], r);
        {
            OSSL_PARAM sp[3];

            sp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mackey, 16);
            sp[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, aad, 13);
            sp[2] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_set_params(ctx, sp);
            printf("cbchmac.%s.rec.set=%d\n", names[n], r);
        }
        memset(ct, 0xee, sizeof(ct));
        {
            int outl = 0, finl = 0;

            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, ct, &outl, in, 64);
            printf("cbchmac.%s.rec.enc=%d\n", names[n], r);
            printf("cbchmac.%s.rec.enc.outl=%d\n", names[n], outl);
            rt_hexf("cbchmac.rec.ct", (int)n, ct, 64);
            ERR_clear_error();
            r = EVP_CipherFinal_ex(ctx, ct + 64, &finl);
            printf("cbchmac.%s.rec.enc.final=%d\n", names[n], r);
            printf("cbchmac.%s.rec.enc.finl=%d\n", names[n], finl);
        }
        EVP_CIPHER_CTX_free(ctx);

        ctx = EVP_CIPHER_CTX_new();
        r = EVP_CipherInit_ex2(ctx, c, key, iv, 0, NULL);
        printf("cbchmac.%s.dec.init=%d\n", names[n], r);
        {
            OSSL_PARAM sp[3];

            sp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mackey, 16);
            sp[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, aad, 13);
            sp[2] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_set_params(ctx, sp);
            printf("cbchmac.%s.dec.set=%d\n", names[n], r);
        }
        memset(pt, 0xee, sizeof(pt));
        {
            int outl = 0;

            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, pt, &outl, ct, 64);
            printf("cbchmac.%s.dec=%d\n", names[n], r);
            printf("cbchmac.%s.dec.outl=%d\n", names[n], outl);
            rt_hexf("cbchmac.rec.pt", (int)n, pt, 64);
            printf("cbchmac.%s.dec.match=%d\n", names[n], memcmp(pt, in, 32) == 0);
        }
        EVP_CIPHER_CTX_free(ctx);

        /*
         * The refusal arm: one flipped ciphertext byte must make the constant-time tag comparison
         * answer 0. It is worth observing separately because the hw returns 0 *after* decrypting,
         * so the buffer contents on this path are part of the answer too.
         */
        ct[40] ^= 0x01;
        ctx = EVP_CIPHER_CTX_new();
        r = EVP_CipherInit_ex2(ctx, c, key, iv, 0, NULL);
        {
            OSSL_PARAM sp[3];

            sp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mackey, 16);
            sp[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, aad, 13);
            sp[2] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_set_params(ctx, sp);
        }
        memset(pt, 0xee, sizeof(pt));
        {
            int outl = 0;

            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, pt, &outl, ct, 64);
            printf("cbchmac.%s.bad=%d\n", names[n], r);
            printf("cbchmac.%s.bad.outl=%d\n", names[n], outl);
            rt_hexf("cbchmac.bad.pt", (int)n, pt, 64);
        }
        EVP_CIPHER_CTX_free(ctx);

        EVP_CIPHER_free(c);
    }
}

/* `rt_errq` is declared with the MAC arms far below; this arm is defined above them. */
static void rt_errq(const char *tag);

/*
 * The three `AES-*-GCM-SIV` rows -- `cipher_aes_gcm_siv.c`, `cipher_aes_gcm_siv_hw.c` and
 * `cipher_aes_gcm_siv_polyval.c`.
 *
 * The **tag is the whole observable**. Everything this construction does -- fetching
 * `AES-*-ECB` under the caller's key to derive `msg_auth_key` and `msg_enc_key`, the POLYVAL
 * multiply that `ossl_polyval_ghash_init`/`_hash` reach through the GHASH table, the
 * `S_s[15] &= 0x7f` masking, the counter block's `|= 0x80` -- exists to produce sixteen bytes that
 * either match an independent implementation or do not. So the arm prints them, alongside the
 * ciphertext the counter mode produces and the three refusal paths.
 *
 * One thing needs saying about the POLYVAL byte order, because it is where a transcription of
 * `cipher_aes_gcm_siv_polyval.c` can go wrong silently. POLYVAL differs from GHASH's field
 * convention by a factor of `x^-128`; the authority expresses that as a single `mulx_ghash` on the
 * byte-reversed authentication key, then hands the result to the *GHASH* table builder. This crate's
 * GCM model carries the field key rather than the Shoup table, so the bridging is a byte-order
 * argument in `src/provider/cipher.rs` -- and this arm is what settles it. The RFC 8452 vectors are
 * the second opinion.
 *
 * Both payload lengths are exercised: 20 bytes takes `!IS16(len)`'s padding arm and 32 takes the
 * exact-multiple arm, and the two hash different POLYVAL inputs. The empty message is here because
 * `aes_gcm_siv_finish` gives it its own path -- the tag is generated by a *final-only* operation.
 */
static void rt_gcm_siv_records(void)
{
    static const char *names[] = {
        "AES-128-GCM-SIV", "AES-192-GCM-SIV", "AES-256-GCM-SIV",
    };
    size_t n;

    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[n], NULL);
        EVP_CIPHER_CTX *ctx;
        unsigned char key[32], nonce[12], aad[13];
        unsigned char in[32], ct[64], pt[64], tag[16], tag2[16];
        unsigned char good_tag[16];
        int r;

        printf("gcm_siv.%s.fetched=%d\n", names[n], c != NULL);
        if (c == NULL)
            continue;

        printf("gcm_siv.%s.flags=%lu\n", names[n], EVP_CIPHER_get_flags(c));
        printf("gcm_siv.%s.keylen=%d\n", names[n], EVP_CIPHER_get_key_length(c));
        printf("gcm_siv.%s.ivlen=%d\n", names[n], EVP_CIPHER_get_iv_length(c));
        printf("gcm_siv.%s.blocksize=%d\n", names[n], EVP_CIPHER_get_block_size(c));
        printf("gcm_siv.%s.mode=%d\n", names[n], EVP_CIPHER_get_mode(c));

        rt_fill(key, 32, 131u + (unsigned int)n);
        rt_fill(nonce, sizeof(nonce), 141u + (unsigned int)n);
        rt_fill(aad, sizeof(aad), 151u + (unsigned int)n);
        rt_fill(in, 32, 161u + (unsigned int)n);

        /* --- the gettable list, on an encrypting context -------------------------------- */
        ctx = EVP_CIPHER_CTX_new();
        r = EVP_CipherInit_ex2(ctx, c, key, nonce, 1, NULL);
        printf("gcm_siv.%s.einit=%d\n", names[n], r);
        {
            size_t kl = 0, tl = 0;
            OSSL_PARAM gp[3];

            gp[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &kl);
            gp[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tl);
            gp[2] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_get_params(ctx, gp);
            printf("gcm_siv.%s.g.get=%d keylen=%zu taglen=%zu\n", names[n], r, kl, tl);
        }
        /* The tag is not readable before a tag exists. */
        {
            OSSL_PARAM tp[2];

            memset(tag, 0xee, sizeof(tag));
            tp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag,
                                                      sizeof(tag));
            tp[1] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_get_params(ctx, tp);
            printf("gcm_siv.%s.tag_early=%d\n", names[n], r);
            rt_errq("gcm_siv.tag_early");
            ERR_clear_error();
        }
        /* `keylen` cannot be modified. */
        {
            size_t other = 17;
            OSSL_PARAM kp[2];

            kp[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &other);
            kp[1] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_set_params(ctx, kp);
            printf("gcm_siv.%s.keylen_set=%d\n", names[n], r);
            rt_errq("gcm_siv.keylen_set");
            ERR_clear_error();
        }
        /* The `speed` flag, which is settable and is the only way a second update is allowed. */
        {
            unsigned int sp = 1;
            OSSL_PARAM spp[2];

            spp[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_SPEED, &sp);
            spp[1] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_set_params(ctx, spp);
            printf("gcm_siv.%s.speed_set=%d\n", names[n], r);
            ERR_clear_error();
        }
        /* The AAD, then twenty bytes of payload: the `!IS16(len)` arm. */
        {
            int outl = 0;

            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)sizeof(aad));
            printf("gcm_siv.%s.aad=%d outl=%d\n", names[n], r, outl);
            ERR_clear_error();
        }
        {
            int outl = 0, finl = 0;

            memset(ct, 0xee, sizeof(ct));
            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, ct, &outl, in, 20);
            printf("gcm_siv.%s.enc20=%d outl=%d\n", names[n], r, outl);
            rt_hexf("gcm_siv.ct20", (int)n, ct, 20);
            ERR_clear_error();
            r = EVP_CipherFinal_ex(ctx, ct + 20, &finl);
            printf("gcm_siv.%s.enc20.final=%d finl=%d\n", names[n], r, finl);
            ERR_clear_error();
        }
        /* The tag, through the params list and then through the classic control. */
        {
            OSSL_PARAM tp[2];

            memset(tag, 0, sizeof(tag));
            tp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag,
                                                      sizeof(tag));
            tp[1] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            r = EVP_CIPHER_CTX_get_params(ctx, tp);
            printf("gcm_siv.%s.tag_get=%d\n", names[n], r);
            rt_hexf("gcm_siv.tag", (int)n, tag, sizeof(tag));
            memcpy(good_tag, tag, sizeof(good_tag));
            ERR_clear_error();

            memset(tag2, 0, sizeof(tag2));
            ERR_clear_error();
            r = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)sizeof(tag2), tag2);
            printf("gcm_siv.%s.tag_ctrl=%d\n", names[n], r);
            rt_hexf("gcm_siv.tagctrl", (int)n, tag2, sizeof(tag2));
            printf("gcm_siv.%s.tag_same=%d\n", names[n], memcmp(tag, tag2, 16) == 0);
            ERR_clear_error();
        }
        EVP_CIPHER_CTX_free(ctx);

        /* --- decrypting: acceptance, then a flipped ciphertext, then a flipped tag ------- */
        {
            static const int which[] = { 0, 1, 2 };
            size_t w;

            for (w = 0; w < sizeof(which) / sizeof(which[0]); w++) {
                unsigned char bad_ct[64], bad_tag[16];
                int outl = 0, finl = 0;

                memcpy(bad_ct, ct, sizeof(bad_ct));
                memcpy(bad_tag, good_tag, sizeof(bad_tag));
                if (which[w] == 1)
                    bad_ct[3] ^= 0x01;
                if (which[w] == 2)
                    bad_tag[7] ^= 0x01;

                ctx = EVP_CIPHER_CTX_new();
                r = EVP_CipherInit_ex2(ctx, c, key, nonce, 0, NULL);
                printf("gcm_siv.%s.dec%d.init=%d\n", names[n], which[w], r);
                {
                    OSSL_PARAM tp[2];

                    tp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, bad_tag,
                                                              sizeof(bad_tag));
                    tp[1] = OSSL_PARAM_construct_end();
                    ERR_clear_error();
                    r = EVP_CIPHER_CTX_set_params(ctx, tp);
                    printf("gcm_siv.%s.dec%d.tag_set=%d\n", names[n], which[w], r);
                    ERR_clear_error();
                }
                ERR_clear_error();
                r = EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)sizeof(aad));
                printf("gcm_siv.%s.dec%d.aad=%d\n", names[n], which[w], r);
                ERR_clear_error();
                memset(pt, 0xee, sizeof(pt));
                r = EVP_CipherUpdate(ctx, pt, &outl, bad_ct, 20);
                printf("gcm_siv.%s.dec%d.upd=%d outl=%d\n", names[n], which[w], r, outl);
                ERR_clear_error();
                r = EVP_CipherFinal_ex(ctx, pt + 20, &finl);
                printf("gcm_siv.%s.dec%d.final=%d finl=%d\n", names[n], which[w], r, finl);
                printf("gcm_siv.%s.dec%d.match=%d\n", names[n], which[w],
                       memcmp(pt, in, 20) == 0);
                rt_hexf("gcm_siv.dec.pt", (int)n, pt, 20);
                ERR_clear_error();
                EVP_CIPHER_CTX_free(ctx);
            }
        }

        /* --- the empty message, whose tag comes from a final-only operation -------------- */
        {
            int finl = 0;

            ctx = EVP_CIPHER_CTX_new();
            r = EVP_CipherInit_ex2(ctx, c, key, nonce, 1, NULL);
            printf("gcm_siv.%s.empty.init=%d\n", names[n], r);
            {
                int outl = 0;

                ERR_clear_error();
                r = EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)sizeof(aad));
                printf("gcm_siv.%s.empty.aad=%d\n", names[n], r);
                ERR_clear_error();
            }
            memset(ct, 0xee, sizeof(ct));
            ERR_clear_error();
            r = EVP_CipherFinal_ex(ctx, ct, &finl);
            printf("gcm_siv.%s.empty.final=%d finl=%d\n", names[n], r, finl);
            ERR_clear_error();
            {
                OSSL_PARAM tp[2];

                memset(tag, 0, sizeof(tag));
                tp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag,
                                                          sizeof(tag));
                tp[1] = OSSL_PARAM_construct_end();
                ERR_clear_error();
                r = EVP_CIPHER_CTX_get_params(ctx, tp);
                printf("gcm_siv.%s.empty.tag_get=%d\n", names[n], r);
                rt_hexf("gcm_siv.emptytag", (int)n, tag, sizeof(tag));
                ERR_clear_error();
            }
            EVP_CIPHER_CTX_free(ctx);
        }

        /* --- a second payload update without `speed`, which the row refuses -------------- */
        {
            int outl = 0;

            ctx = EVP_CIPHER_CTX_new();
            r = EVP_CipherInit_ex2(ctx, c, key, nonce, 1, NULL);
            printf("gcm_siv.%s.twice.init=%d\n", names[n], r);
            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)sizeof(aad));
            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, ct, &outl, in, 20);
            printf("gcm_siv.%s.twice.first=%d\n", names[n], r);
            ERR_clear_error();
            /*
             * `!ctx->speed && ctx->used_enc` is the gate, and it refuses **silently**: the hw
             * returns 0 and queues nothing, so `outl` keeps whatever the previous arm left and the
             * error queue is empty. Both halves are printed.
             */
            outl = -12345;
            r = EVP_CipherUpdate(ctx, ct, &outl, in, 20);
            printf("gcm_siv.%s.twice.second=%d outl=%d\n", names[n], r, outl);
            rt_errq("gcm_siv.twice.second");
            ERR_clear_error();
            EVP_CIPHER_CTX_free(ctx);
        }

        /* --- one thirty-two byte message, the `IS16(len)` arm --------------------------- */
        {
            int outl = 0, finl = 0;

            ctx = EVP_CIPHER_CTX_new();
            r = EVP_CipherInit_ex2(ctx, c, key, nonce, 1, NULL);
            printf("gcm_siv.%s.m32.init=%d\n", names[n], r);
            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)sizeof(aad));
            printf("gcm_siv.%s.m32.aad=%d\n", names[n], r);
            memset(ct, 0xee, sizeof(ct));
            ERR_clear_error();
            r = EVP_CipherUpdate(ctx, ct, &outl, in, 32);
            printf("gcm_siv.%s.m32.enc=%d outl=%d\n", names[n], r, outl);
            rt_hexf("gcm_siv.ct32", (int)n, ct, 32);
            ERR_clear_error();
            r = EVP_CipherFinal_ex(ctx, ct + 32, &finl);
            printf("gcm_siv.%s.m32.final=%d finl=%d\n", names[n], r, finl);
            ERR_clear_error();
            {
                OSSL_PARAM tp[2];

                memset(tag, 0, sizeof(tag));
                tp[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag,
                                                          sizeof(tag));
                tp[1] = OSSL_PARAM_construct_end();
                ERR_clear_error();
                r = EVP_CIPHER_CTX_get_params(ctx, tp);
                printf("gcm_siv.%s.m32.tag_get=%d\n", names[n], r);
                rt_hexf("gcm_siv.tag32", (int)n, tag, sizeof(tag));
                ERR_clear_error();
            }
            EVP_CIPHER_CTX_free(ctx);
        }

        EVP_CIPHER_free(c);
    }
}

static void rt_deflt_row_census(void)
{
    static const char *rows[] = {
        "NULL", "AES-256-ECB", "AES-192-ECB", "AES-128-ECB",
        "AES-256-CBC", "AES-192-CBC", "AES-128-CBC", "AES-128-CBC-CTS",
        "AES-192-CBC-CTS", "AES-256-CBC-CTS", "AES-256-OFB", "AES-192-OFB",
        "AES-128-OFB", "AES-256-CFB", "AES-192-CFB", "AES-128-CFB",
        "AES-256-CFB1", "AES-192-CFB1", "AES-128-CFB1", "AES-256-CFB8",
        "AES-192-CFB8", "AES-128-CFB8", "AES-256-CTR", "AES-192-CTR",
        "AES-128-CTR", "AES-256-XTS", "AES-128-XTS", "AES-256-OCB",
        "AES-192-OCB", "AES-128-OCB", "AES-128-SIV", "AES-192-SIV",
        "AES-256-SIV",
        /* The `AES-*-GCM-SIV` trio, `defltprov.c:198-200`, between the `AES-*-SIV` three and the
         * `AES-*-GCM` three. The three below it were Phase 9's on `RAND_bytes_ex` and listed-and-
         * skipped until the GCM engine landed (D278); they are entries now that the rows are. */
        "AES-128-GCM-SIV", "AES-192-GCM-SIV", "AES-256-GCM-SIV",
        "AES-256-GCM", "AES-192-GCM", "AES-128-GCM",
        "AES-256-CCM", "AES-192-CCM", "AES-128-CCM",
        "AES-256-WRAP", "AES-192-WRAP", "AES-128-WRAP", "AES-256-WRAP-PAD",
        "AES-192-WRAP-PAD", "AES-128-WRAP-PAD", "AES-256-WRAP-INV", "AES-192-WRAP-INV",
        "AES-128-WRAP-INV", "AES-256-WRAP-PAD-INV", "AES-192-WRAP-PAD-INV", "AES-128-WRAP-PAD-INV",
        /* The thirteen `ALGC(...)` `AES-*-CBC-HMAC-*` rows, `defltprov.c:220-245`, in their own
         * order. The four non-ETM rows are published on this host; the nine ETM rows are dropped
         * by the profile's capability predicates, so their `fetched` is 0 on *both* sides and the
         * arm's remaining observations are skipped for them (D276). */
        "AES-128-CBC-HMAC-SHA1", "AES-256-CBC-HMAC-SHA1",
        "AES-128-CBC-HMAC-SHA256", "AES-256-CBC-HMAC-SHA256",
        "AES-128-CBC-HMAC-SHA1-ETM", "AES-192-CBC-HMAC-SHA1-ETM", "AES-256-CBC-HMAC-SHA1-ETM",
        "AES-128-CBC-HMAC-SHA256-ETM", "AES-192-CBC-HMAC-SHA256-ETM",
        "AES-256-CBC-HMAC-SHA256-ETM",
        "AES-128-CBC-HMAC-SHA512-ETM", "AES-192-CBC-HMAC-SHA512-ETM",
        "AES-256-CBC-HMAC-SHA512-ETM",
        /* The authority's `deflt_ciphers[]` order again: the `ARIA-*` rows land between the
         * AES-CBC-HMAC `ALGC` rows and `CAMELLIA`. The three GCM rows, `defltprov.c:247-249`,
         * precede the CCM three; they were Phase 9's on `RAND_bytes_ex` and are listed here now
         * that their engine has landed (D270). */
        "ARIA-256-GCM", "ARIA-192-GCM", "ARIA-128-GCM",
        "ARIA-256-CCM", "ARIA-192-CCM", "ARIA-128-CCM",
        "ARIA-256-ECB", "ARIA-192-ECB", "ARIA-128-ECB",
        "ARIA-256-CBC", "ARIA-192-CBC", "ARIA-128-CBC",
        "ARIA-256-OFB", "ARIA-192-OFB", "ARIA-128-OFB",
        "ARIA-256-CFB", "ARIA-192-CFB", "ARIA-128-CFB",
        "ARIA-256-CFB1", "ARIA-192-CFB1", "ARIA-128-CFB1",
        "ARIA-256-CFB8", "ARIA-192-CFB8", "ARIA-128-CFB8",
        "ARIA-256-CTR", "ARIA-192-CTR", "ARIA-128-CTR",
        "CAMELLIA-256-ECB", "CAMELLIA-192-ECB", "CAMELLIA-128-ECB", "CAMELLIA-256-CBC",
        "CAMELLIA-192-CBC", "CAMELLIA-128-CBC", "CAMELLIA-128-CBC-CTS", "CAMELLIA-192-CBC-CTS",
        "CAMELLIA-256-CBC-CTS", "CAMELLIA-256-OFB", "CAMELLIA-192-OFB", "CAMELLIA-128-OFB",
        "CAMELLIA-256-CFB", "CAMELLIA-192-CFB", "CAMELLIA-128-CFB", "CAMELLIA-256-CFB1",
        "CAMELLIA-192-CFB1", "CAMELLIA-128-CFB1", "CAMELLIA-256-CFB8", "CAMELLIA-192-CFB8",
        "CAMELLIA-128-CFB8", "CAMELLIA-256-CTR", "CAMELLIA-192-CTR", "CAMELLIA-128-CTR",
        "DES-EDE3-ECB", "DES-EDE3-CBC", "DES-EDE3-OFB", "DES-EDE3-CFB",
        "DES-EDE3-CFB8", "DES-EDE3-CFB1",
        /* `defltprov.c:308`: the `DES3-WRAP` row lands between the EDE3 six and the EDE four. It was
         * Phase 8's obligation on `RAND_bytes_ex` (`cipher_tdes_wrap.c`'s `des_ede3_wrap` fills the
         * wrap IV from it) and its engine is Phase 9's, `src/provider/cipher_tdes_wrap.rs`. */
        "DES3-WRAP",
        "DES-EDE-ECB", "DES-EDE-CBC",
        "DES-EDE-OFB", "DES-EDE-CFB",
        /* `SM4-GCM` (`defltprov.c:315`) precedes `SM4-CCM`; it was Phase 9's on `RAND_bytes_ex`
         * and is listed here now that its engine has landed. The `SM4-XTS` row follows
         * `SM4-CFB` and has not landed. */
        "SM4-GCM", "SM4-CCM",
        /* The authority's `deflt_ciphers[]` order, which is the order this list is compared in:
         * the `SM4-*` rows land between the ARIA family and `ChaCha20`. */
        "SM4-ECB", "SM4-CBC", "SM4-CTR", "SM4-OFB", "SM4-CFB", "SM4-XTS",
        "ChaCha20",
        /* The authority's last cipher row, `defltprov.c:327`, immediately after `ChaCha20` and
         * inside the same `#ifndef OPENSSL_NO_CHACHA`/`#ifndef OPENSSL_NO_POLY1305` block. A plain
         * `ALG`, not an `ALGC`: no capability predicate, so it is published on every host. */
        "ChaCha20-Poly1305",
    };
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, rows[i], NULL);

        printf("defltrow.%s.fetched=%d\n", rows[i], c != NULL);
        if (c == NULL)
            continue;
        printf("defltrow.%s.keylen=%d\n", rows[i], EVP_CIPHER_get_key_length(c));
        printf("defltrow.%s.ivlen=%d\n", rows[i], EVP_CIPHER_get_iv_length(c));
        printf("defltrow.%s.blocksize=%d\n", rows[i], EVP_CIPHER_get_block_size(c));
        printf("defltrow.%s.mode=%d\n", rows[i], EVP_CIPHER_get_mode(c));

        /*
         * The three published parameter lists for the row. `data_size` is part of what a caller
         * reads -- `OSSL_PARAM_size_t` carries `sizeof(size_t)` and `OSSL_PARAM_uint` carries
         * `sizeof(unsigned int)`, which are different numbers for the same
         * `OSSL_PARAM_UNSIGNED_INTEGER` type -- so the *whole* descriptor is printed and not just
         * the key. The context is created with a NULL key and IV: the cipher is assigned to the
         * context before `einit` runs, so the lists are reachable even when the init itself
         * refuses, and the refusal is printed rather than suppressed.
         */
        rt_param_list("defltrow", rows[i], "gp", EVP_CIPHER_gettable_params(c));
        {
            EVP_CIPHER_CTX *cc = EVP_CIPHER_CTX_new();
            int r = 0;

            if (cc != NULL) {
                ERR_clear_error();
                r = EVP_CipherInit_ex2(cc, c, NULL, NULL, 1, NULL);
                ERR_clear_error();
            }
            printf("defltrow.%s.ctxinit=%d\n", rows[i], r);
            rt_param_list("defltrow", rows[i], "cgp",
                          EVP_CIPHER_CTX_gettable_params(cc));
            rt_param_list("defltrow", rows[i], "csp",
                          EVP_CIPHER_CTX_settable_params(cc));
            EVP_CIPHER_CTX_free(cc);
        }
        EVP_CIPHER_free(c);
    }
}

/*
 * The property definition every default-provider row carries, which is `"provider=default"` and is
 * observable through the property query rather than only through the table. The authority spells it
 * with `#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }`, so a row
 * published with a NULL property is not merely missing a string: a fetch whose query is
 * `provider=default` stops resolving through it, and one whose query is `provider!=default` starts
 * resolving when it should not. Both directions are observed here, for a cipher, a digest and a MAC,
 * because the three tables are built by three different pieces of code (D247).
 */
static void rt_deflt_properties(void)
{
    static const struct {
        const char *op;
        const char *name;
    } rows[] = {
        { "cipher", "AES-128-CBC" },
        { "digest", "SHA256" },
        { "mac",    "CMAC" },
        { "mac",    "HMAC" },
        { "mac",    "BLAKE2BMAC" },
        { "mac",    "BLAKE2SMAC" },
        { "mac",    "POLY1305" },
        { "mac",    "KMAC-128" },
        { "mac",    "KMAC-256" },
    };
    static const char *props[] = { NULL, "provider=default", "provider!=default" };
    size_t i, j;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        for (j = 0; j < sizeof(props) / sizeof(props[0]); j++) {
            const char *prop = props[j];
            int ok;

            if (strcmp(rows[i].op, "cipher") == 0) {
                EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, rows[i].name, prop);

                ok = c != NULL;
                EVP_CIPHER_free(c);
            } else if (strcmp(rows[i].op, "digest") == 0) {
                EVP_MD *m = EVP_MD_fetch(NULL, rows[i].name, prop);

                ok = m != NULL;
                EVP_MD_free(m);
            } else {
                EVP_MAC *m = EVP_MAC_fetch(NULL, rows[i].name, prop);

                ok = m != NULL;
                EVP_MAC_free(m);
            }
            printf("defltprop.%s.%s.%s=%d\n", rows[i].op, rows[i].name,
                   prop == NULL ? "null" : (strcmp(prop, "provider=default") == 0 ? "eq" : "ne"),
                   ok);
        }
    }
}

/*
 * The `SIPHASH` row, driven through `EVP_MAC` rather than through the primitive: a fetch, the three
 * ctx-params getters, the three settable ones, a known-answer arm at five message lengths (the
 * expected tags are the authority's own output, generated by compiling the pinned
 * `crypto/siphash/siphash.c` standalone), and the two refusals that are easy to lose -- a key that
 * is not sixteen octets, and a final whose buffer is smaller than the tag.
 *
 * The eight- and sixteen-octet output lengths are **two constructions, not one truncated**: the
 * primitive xor's `0xee` into `v1` at init and `0xee` into `v2` at final for the sixteen-octet
 * form where the eight-octet form xor's `0xff`. So both are observed.
 */
static void rt_deflt_siphash(void)
{
    static const struct {
        int len;
        unsigned char tag[8];
    } kat[] = {
        { 0, { 0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72 } },
        { 1, { 0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74 } },
        { 15, { 0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1 } },
        { 16, { 0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f } },
        { 63, { 0x72, 0x45, 0x06, 0xeb, 0x4c, 0x32, 0x8a, 0x95 } },
    };
    static const unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char msg[64];
    unsigned char out[16];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "SIPHASH", NULL);
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[2];
    size_t i, outl;
    unsigned int rounds;

    printf("defltsiphash.fetched=%d\n", mac != NULL);
    if (mac == NULL)
        return;
    ctx = EVP_MAC_CTX_new(mac);
    printf("defltsiphash.ctx=%d\n", ctx != NULL);
    if (ctx == NULL) {
        EVP_MAC_free(mac);
        return;
    }

    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)i;

    /* The two round counts read back as the primitive's defaults before anything is set. */
    rounds = 0;
    params[0] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &rounds);
    params[1] = OSSL_PARAM_construct_end();
    printf("defltsiphash.c.default=%d:%u\n",
           EVP_MAC_CTX_get_params(ctx, params), rounds);
    rounds = 0;
    params[0] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &rounds);
    printf("defltsiphash.d.default=%d:%u\n",
           EVP_MAC_CTX_get_params(ctx, params), rounds);

    /* A key that is not sixteen octets is refused. */
    printf("defltsiphash.key15=%d\n", EVP_MAC_init(ctx, key, 15, NULL));
    EVP_MAC_CTX_free(ctx);
    ctx = EVP_MAC_CTX_new(mac);

    /* The eight-octet known answers, each a fresh context. */
    for (i = 0; i < sizeof(kat) / sizeof(kat[0]); i++) {
        memset(out, 0, sizeof(out));
        outl = 0;
        if (EVP_MAC_init(ctx, key, sizeof(key), NULL) != 1
            || EVP_MAC_update(ctx, msg, (size_t)kat[i].len) != 1
            || EVP_MAC_final(ctx, out, &outl, sizeof(out)) != 1) {
            printf("defltsiphash.kat%d.init=0\n", kat[i].len);
            continue;
        }
        printf("defltsiphash.kat%d.len=%zu\n", kat[i].len, outl);
        printf("defltsiphash.kat%d.tag=%d\n", kat[i].len,
               memcmp(out, kat[i].tag, 8) == 0);
        rt_hex("defltsiphash.katv", out, 8);
    }

    /* A final whose buffer is one byte short of the tag is refused. */
    outl = 0;
    printf("defltsiphash.short=%d\n", EVP_MAC_final(ctx, out, &outl, 7));
    printf("defltsiphash.short.len=%zu\n", outl);

    /* The sixteen-octet form, and `size` as a settable. */
    {
        OSSL_PARAM set[2];
        size_t size = 8;

        set[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
        set[1] = OSSL_PARAM_construct_end();
        printf("defltsiphash.set.size8=%d\n", EVP_MAC_CTX_set_params(ctx, set));
        outl = 0;
        if (EVP_MAC_init(ctx, key, sizeof(key), NULL) == 1
            && EVP_MAC_update(ctx, msg, 16) == 1
            && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1) {
            printf("defltsiphash.size8.len=%zu\n", outl);
            rt_hex("defltsiphash.size8.tag", out, outl);
        } else {
            printf("defltsiphash.size8.enclen=0\n");
        }
        size = 12;
        printf("defltsiphash.set.size12=%d\n", EVP_MAC_CTX_set_params(ctx, set));
    }

    /* Default 16-octet output, which is a different construction from the 8-octet one. */
    EVP_MAC_CTX_free(ctx);
    ctx = EVP_MAC_CTX_new(mac);
    outl = 0;
    if (EVP_MAC_init(ctx, key, sizeof(key), NULL) == 1
        && EVP_MAC_update(ctx, msg, 16) == 1
        && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1) {
        printf("defltsiphash.full16.len=%zu\n", outl);
        rt_hex("defltsiphash.full16.tag", out, outl);
    } else {
        printf("defltsiphash.full16.enclen=0\n");
    }

    /* Explicit round counts, which change the tag. */
    EVP_MAC_CTX_free(ctx);
    ctx = EVP_MAC_CTX_new(mac);
    {
        unsigned int c = 2, d = 4;
        OSSL_PARAM set[3];

        set[0] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &c);
        set[1] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &d);
        set[2] = OSSL_PARAM_construct_end();
        printf("defltsiphash.set.rounds=%d\n", EVP_MAC_CTX_set_params(ctx, set));
        outl = 0;
        if (EVP_MAC_init(ctx, key, sizeof(key), NULL) == 1
            && EVP_MAC_update(ctx, msg, 16) == 1
            && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1) {
            rt_hex("defltsiphash.rounds.tag", out, outl);
        } else {
            printf("defltsiphash.rounds.enclen=0\n");
        }
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

/* The drained queue, normalised the one way both sides can hold: library and reason as numbers,
 * the authority's three debug strings verbatim, and the entry count. Declared before the `POLY1305`,
 * `BLAKE2` and `HMAC` arms, which drain queues, and defined with the dispatch arm below. */
static void rt_errq(const char *tag);

/*
 * The `POLY1305` row. Two things about it are unlike every other MAC row here.
 *
 * It publishes the **provider-level** `GETTABLE_PARAMS`/`GET_PARAMS` pair and no ctx-params getter
 * at all -- so `EVP_MAC_CTX_gettable_params` answers NULL while `EVP_MAC_gettable_params` answers a
 * one-entry list. GMAC is the only other row with that shape, and GMAC's row is withheld.
 *
 * And its state machine is two flags rather than one. `key_set` gates an update or a final with
 * `PROV_R_NO_KEY_SET`, and `updated` -- set by *both* of them -- is what makes a second
 * `EVP_MAC_init` **without a key** refuse. So an update with no key raises *and* leaves `updated`
 * clear, which is what keeps a later keyless init possible; both halves of that are observed.
 *
 * The empty-message case is here because the construction gives its answer directly: with no
 * message the accumulator is zero and `emit` returns `(0 + nonce) mod 2^128`, so the tag is exactly
 * the key's second half. That is a check on `Init`'s word order and on `emit` that needs no vector.
 */
static void rt_deflt_poly1305(void)
{
    static const unsigned char key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
        0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
        0x41, 0x49, 0xf5, 0x1b
    };
    static const char *msg = "Cryptographic Forum Research Group";
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    EVP_MAC_CTX *ctx;
    unsigned char out[64];
    OSSL_PARAM list[2], set[3];
    size_t i, outl;

    printf("defltpoly.fetched=%d\n", mac != NULL);
    if (mac == NULL)
        return;

    ctx = EVP_MAC_CTX_new(mac);
    printf("defltpoly.ctx=%d\n", ctx != NULL);
    if (ctx == NULL) {
        EVP_MAC_free(mac);
        return;
    }

    /* The provider-level getter list, and the ctx-level pair that is absent. */
    rt_param_list("defltpoly", "x", "gp", EVP_MAC_gettable_params(mac));
    rt_param_list("defltpoly", "x", "cgp", EVP_MAC_CTX_gettable_params(ctx));
    rt_param_list("defltpoly", "x", "csp", EVP_MAC_CTX_settable_params(ctx));
    /*
     * The same one-entry descriptor through both getters. The context call returns 1 and leaves
     * the output untouched because this row has no ctx-level getter at all; the method-level call
     * is the one that reaches `poly1305_get_params` and writes 16. The pair is the observation
     * that the row is shaped as a *provider*-level getter.
     */
    {
        size_t sz = 0;

        list[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        list[1] = OSSL_PARAM_construct_end();
        printf("defltpoly.get.size=%d:%zu\n", EVP_MAC_CTX_get_params(ctx, list), sz);
        sz = 0;
        list[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        list[1] = OSSL_PARAM_construct_end();
        printf("defltpoly.getp.size=%d:%zu\n", EVP_MAC_get_params(mac, list), sz);
    }

    /* The RFC 8439 §2.5.2 vector, one-shot. */
    outl = 0;
    if (EVP_MAC_init(ctx, key, sizeof(key), NULL) == 1
        && EVP_MAC_update(ctx, (const unsigned char *)msg, strlen(msg)) == 1
        && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1) {
        printf("defltpoly.rfc.len=%zu\n", outl);
        rt_hex("defltpoly.rfc.tag", out, outl);
    } else {
        printf("defltpoly.rfc.enclen=0\n");
    }

    /* The same message split at every boundary, and byte at a time. */
    for (i = 0; i <= strlen(msg); i++) {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        outl = 0;
        if (EVP_MAC_init(c, key, sizeof(key), NULL) == 1
            && EVP_MAC_update(c, (const unsigned char *)msg, i) == 1
            && EVP_MAC_update(c, (const unsigned char *)msg + i, strlen(msg) - i) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1)
            rt_hex("defltpoly.split", out, outl);
        else
            printf("defltpoly.split.enclen=0\n");
        EVP_MAC_CTX_free(c);
    }
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        outl = 0;
        if (EVP_MAC_init(c, key, sizeof(key), NULL) == 1) {
            for (i = 0; i < strlen(msg); i++)
                EVP_MAC_update(c, (const unsigned char *)msg + i, 1);
            if (EVP_MAC_final(c, out, &outl, sizeof(out)) == 1)
                rt_hex("defltpoly.bytewise", out, outl);
            else
                printf("defltpoly.bytewise.enclen=0\n");
        }
        EVP_MAC_CTX_free(c);
    }

    /* An empty message tags to the key's nonce half, which the construction gives directly. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        outl = 0;
        if (EVP_MAC_init(c, key, sizeof(key), NULL) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("defltpoly.empty.len=%zu\n", outl);
            rt_hex("defltpoly.empty.tag", out, outl);
        } else {
            printf("defltpoly.empty.enclen=0\n");
        }
        EVP_MAC_CTX_free(c);
    }

    /* A key delivered through the parameter array, and a zero-length update. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        set[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)key, sizeof(key));
        set[1] = OSSL_PARAM_construct_end();
        printf("defltpoly.pkey.set=%d\n", EVP_MAC_CTX_set_params(c, set));
        outl = 0;
        if (EVP_MAC_init(c, NULL, 0, NULL) == 1
            && EVP_MAC_update(c, (const unsigned char *)msg, 0) == 1
            && EVP_MAC_update(c, (const unsigned char *)msg, strlen(msg)) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("defltpoly.pkey.len=%zu\n", outl);
            rt_hex("defltpoly.pkey.tag", out, outl);
        } else {
            printf("defltpoly.pkey.enclen=0\n");
        }
        EVP_MAC_CTX_free(c);
    }

    /* The duplicate, mid-message. */
    {
        EVP_MAC_CTX *a0 = EVP_MAC_CTX_new(mac);
        EVP_MAC_CTX *b0;
        int ok_copy, ok_orig;
        size_t outl2 = 0;

        printf("defltpoly.dup.init=%d\n", EVP_MAC_init(a0, key, sizeof(key), NULL));
        printf("defltpoly.dup.update=%d\n", EVP_MAC_update(a0, (const unsigned char *)msg, 16));
        b0 = EVP_MAC_CTX_dup(a0);
        printf("defltpoly.dup.made=%d\n", b0 != NULL);
        if (b0 != NULL) {
            printf("defltpoly.dup.copy.update=%d\n",
                   EVP_MAC_update(b0, (const unsigned char *)msg + 16, strlen(msg) - 16));
            outl = 0;
            outl2 = 0;
            ok_copy = EVP_MAC_final(b0, out, &outl, sizeof(out));
            printf("defltpoly.dup.copy.final=%d\n", ok_copy);
            if (ok_copy)
                rt_hex("defltpoly.dup.copytag", out, outl);
            ok_orig = EVP_MAC_final(a0, out, &outl2, sizeof(out));
            printf("defltpoly.dup.orig.final=%d\n", ok_orig);
            if (ok_orig)
                rt_hex("defltpoly.dup.origtag", out, outl2);
            EVP_MAC_CTX_free(b0);
        }
        EVP_MAC_CTX_free(a0);
    }

    EVP_MAC_CTX_free(ctx);

    /* The refusals, each with its queue. */
    {
        EVP_MAC_CTX *c;
        int one = 1;
        OSSL_PARAM a[3];

        /* A key of the wrong length, at both ends: the length half of one raise coordinate. */
        c = EVP_MAC_CTX_new(mac);
        ERR_clear_error();
        printf("defltpoly.key0=%d\n", EVP_MAC_init(c, key, 0, NULL));
        rt_errq("poly_key0");
        ERR_clear_error();
        printf("defltpoly.key31=%d\n", EVP_MAC_init(c, key, 31, NULL));
        rt_errq("poly_key31");
        ERR_clear_error();
        printf("defltpoly.key33=%d\n", EVP_MAC_init(c, key, 33, NULL));
        rt_errq("poly_key33");

        /*
         * The NULL half of that *same* coordinate, which `EVP_MAC_init` structurally cannot
         * reach: a NULL key there takes the keyless re-init path and never calls
         * `poly1305_setkey`. Only a `key` descriptor whose `data` is NULL reaches it, so that is
         * what is observed. Two arms for one raise site because they are two distinct public
         * calls, and observing only the length half would leave the `key == NULL` disjunct
         * unobserved while looking covered.
         */
        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, NULL, sizeof(key));
        a[1] = OSSL_PARAM_construct_end();
        printf("defltpoly.set.keynull=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("poly_set_keynull");

        /*
         * `EVP_MAC_init` with a NULL key is *not* a refusal: `poly1305_init` skips `setkey`
         * entirely and answers `ctx->updated == 0`, so on a context where nothing has been
         * updated it succeeds -- and `keylen` is ignored rather than checked, which is why this
         * is printed instead of assumed.
         */
        ERR_clear_error();
        printf("defltpoly.keylessinit=%d\n", EVP_MAC_init(c, NULL, 32, NULL));
        rt_errq("poly_keylessinit");

        /* An update and a final with no key: two coordinates for one reason. */
        ERR_clear_error();
        printf("defltpoly.upd.nokey=%d\n", EVP_MAC_update(c, (const unsigned char *)msg, 1));
        rt_errq("poly_upd_nokey");
        ERR_clear_error();
        outl = 0;
        printf("defltpoly.fin.nokey=%d\n", EVP_MAC_final(c, out, &outl, sizeof(out)));
        rt_errq("poly_fin_nokey");

        /*
         * The keyless second init. `updated` is clear while the updates above were refused, so
         * this succeeds; after a *successful* update it must not, and both are observed.
         */
        printf("defltpoly.reinit.beforekey=%d\n", EVP_MAC_init(c, NULL, 0, NULL));
        printf("defltpoly.reinit.key=%d\n", EVP_MAC_init(c, key, sizeof(key), NULL));
        printf("defltpoly.reinit.update=%d\n",
               EVP_MAC_update(c, (const unsigned char *)msg, 1));
        ERR_clear_error();
        printf("defltpoly.reinit.afterupdate=%d\n", EVP_MAC_init(c, NULL, 0, NULL));
        rt_errq("poly_reinit_afterupdate");

        /* A `key` that is not an octet string, and a repeated one. */
        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_KEY, &one);
        a[1] = OSSL_PARAM_construct_end();
        printf("defltpoly.set.keytype=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("poly_set_keytype");

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)key, sizeof(key));
        a[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)key, sizeof(key));
        a[2] = OSSL_PARAM_construct_end();
        printf("defltpoly.set.repeat=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("poly_set_repeat");

        /*
         * The provider-level getter's own repeated-parameter site, reached through
         * `EVP_MAC_get_params` on the **method**, not `EVP_MAC_CTX_get_params` on the context.
         * This row publishes no ctx-level getter, so the context call would answer 1 without
         * entering the row at all -- an arm that reads as coverage and is not.
         */
        {
            size_t sz = 0;
            OSSL_PARAM g[3];

            g[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
            g[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
            g[2] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            printf("defltpoly.getp.repeat=%d\n", EVP_MAC_get_params(mac, g));
            rt_errq("poly_getp_repeat");
        }
        EVP_MAC_CTX_free(c);
    }

    /* A final whose buffer is smaller than the tag, refused by `evp_mac_final` itself. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        EVP_MAC_init(c, key, sizeof(key), NULL);
        EVP_MAC_update(c, (const unsigned char *)msg, 4);
        ERR_clear_error();
        outl = 0;
        printf("defltpoly.final.short=%d\n", EVP_MAC_final(c, out, &outl, 7));
        rt_errq("poly_final_short");
        EVP_MAC_CTX_free(c);
    }

    EVP_MAC_free(mac);
}

/*
 * The `KMAC-128` and `KMAC-256` rows -- one implementation published twice.
 *
 * Five things about this arm are the reason it is not a copy of the CMAC one.
 *
 * **The row is a shell over the `KECCAK-KMAC-*` digest**, so what the authority's own text does at
 * `new` is fetch a digest by name from a one-entry descriptor, and a row whose digest fails to resolve
 * is a row that answers NULL rather than a row that answers a wrong tag. The fetch-by-alias and
 * fetch-by-OID arms are here because `PROV_NAMES_KMAC_128` carries `KMAC128` and an OID, and D244 is
 * what a short alias sequence costs.
 *
 * **The default customisation string is installed from inside `init`**, through the row's own setter,
 * with its return value discarded. So a row nobody configured still has a two-byte encoded custom
 * (`left_encode(0)`), and "no custom" and "empty custom" are the *same* thing here -- unlike
 * BLAKE2MAC's `custom`, where the descriptor is read directly. The three custom arms below are
 * "leave it", "set the empty string" and "set twenty-one bytes", and the last two are compared with
 * each other rather than only with the authority.
 *
 * **`size` can change after `init` and before `final`.** The encoded length is written by `final`, not
 * by `init`, so `EVP_MAC_CTX_set_params(size)` between the two changes the tag *and* the buffer
 * `evp_mac_final` demands. That is why the `size.afterinit` arm exists rather than being folded into
 * the one-shot: it is a different code path with a different answer.
 *
 * **`final` ignores the `outsize` it is handed.** The bound a caller sees comes from `EVP_MAC_final`'s
 * `outsize < macsize` test, which reads this row's `size` back through `get_ctx_params`. So a short
 * buffer is refused at the EVP layer, with an EVP error, before the row runs -- and the arm prints the
 * queue rather than only the return, because the two layers raise different libraries.
 *
 * **The row's digest is fixed and its `digest` parameter is not a settable key.** `hmac_prov.c` has a
 * `digest` arm that re-fetches; `kmac_prov.c` has none, so `set_params(digest)` is silently ignored
 * and the tag is unchanged. The `set.digest` arm measures that, because a transcription that had
 * copied HMAC's key list would answer every other arm identically.
 *
 * The NIST vectors are the SP 800-185 samples, and the probe prints the tags rather than the expected
 * values: the differential court compares this transcript against the authority's, and the published
 * expectations belong to the construction-vector plane. The inputs are the standard's own
 * (`K` = `40..5F`, `X` = `00010203` or `00..C7`, `S` = `"My Tagged Application"`).
 */

/* `K` -- SP 800-185's sample key, `40 41 42 .. 5E 5F`, thirty-two bytes. */
static const unsigned char kmac_key[32] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f
};

/* `X` = `00010203`. */
static const unsigned char kmac_msg_short[4] = { 0x00, 0x01, 0x02, 0x03 };

/* `S` = `"My Tagged Application"`, twenty-one bytes and no NUL in the descriptor. */
static const char kmac_custom_text[] = "My Tagged Application";

/* `X` = `00 01 02 .. C7`, the standard's 200-byte sample message. */
static void kmac_msg_long(unsigned char *out, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        out[i] = (unsigned char)i;
}

/* A hex line whose name is `<prefix>.<which>`, so a diff localises the arm that moved. */
static void rt_hex_w(const char *prefix, const char *which, const unsigned char *p, size_t n)
{
    char buf[96];

    snprintf(buf, sizeof(buf), "%s.%s", prefix, which);
    rt_hex(buf, p, n);
}

/*
 * One row's whole surface. `outbytes` and `blocksize` are the two numbers the row's *own* digest
 * determines, so they are parameters rather than constants -- the pair is the whole difference between
 * the two rows and printing both is what says so.
 */
static void rt_deflt_kmac_one(const char *name, const char *label, const char *alias,
                              const char *oid, size_t outbytes, size_t blocksize)
{
    char tag[64];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, name, NULL);
    EVP_MAC_CTX *ctx;
    unsigned char msg[200], out[128];
    OSSL_PARAM list[4], set[4];
    size_t i, outl;
    int one = 1;

    printf("deflt%s.fetched=%d\n", label, mac != NULL);
    if (mac == NULL)
        return;
    /* The whole alias sequence is the contract, not the primary name (D244). */
    {
        EVP_MAC *a = EVP_MAC_fetch(NULL, alias, NULL);
        EVP_MAC *o = EVP_MAC_fetch(NULL, oid, NULL);

        printf("deflt%s.alias=%d\n", label, a != NULL);
        printf("deflt%s.oid=%d\n", label, o != NULL);
        EVP_MAC_free(a);
        EVP_MAC_free(o);
    }

    ctx = EVP_MAC_CTX_new(mac);
    printf("deflt%s.ctx=%d\n", label, ctx != NULL);
    if (ctx == NULL) {
        EVP_MAC_free(mac);
        return;
    }

    /*
     * The ctx-level pair, which this row *does* publish -- unlike GMAC's and POLY1305's
     * provider-level one. That distinction is what decides whether `EVP_MAC_CTX_get_mac_size` can
     * answer at all, and it bounds `EVP_MAC_final`.
     */
    rt_param_list("defltkmac", label, "gp", EVP_MAC_CTX_gettable_params(ctx));
    rt_param_list("defltkmac", label, "sp", EVP_MAC_CTX_settable_params(ctx));

    /* `size` and `block-size`, the second written with `set_int` into a `size_t` list entry. */
    {
        size_t sz = 0;
        int bs = -1;

        list[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        list[1] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_BLOCK_SIZE, &bs);
        list[2] = OSSL_PARAM_construct_end();
        printf("deflt%s.get=%d:%zu:%d\n", label, EVP_MAC_CTX_get_params(ctx, list), sz, bs);
    }
    /* The same key through a `size_t` descriptor, which is what the *list* declares. */
    {
        size_t bs = 0;

        list[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &bs);
        list[1] = OSSL_PARAM_construct_end();
        printf("deflt%s.getb.szt=%d:%zu\n", label, EVP_MAC_CTX_get_params(ctx, list), bs);
    }
    printf("deflt%s.macsize=%zu\n", label, EVP_MAC_CTX_get_mac_size(ctx));
    printf("deflt%s.blocksize=%zu\n", label, EVP_MAC_CTX_get_block_size(ctx));

    kmac_msg_long(msg, sizeof(msg));

    /*
     * The fixed-output SP 800-185 samples this row owns, one-shot.
     *
     * **The customisation string is passed to `EVP_MAC_init`, not set afterwards.** `kmac_init`
     * consumes `custom` when it bytepads the digest's prefix, so a `set_params(custom)` *after* the
     * init cannot change the tag at all -- the first version of this arm did exactly that and every
     * "different custom" case came out identical to the default, which looks like coverage and is
     * not. The authority's own comment says the same thing in words ("All other params should be set
     * before init"). The post-init arm below is kept, and inverted: it asserts the tag is *unchanged*.
     */
    {
        struct {
            const unsigned char *x;
            size_t xlen;
            const char *custom; /* NULL = leave the default */
        } cases[3];
        size_t n = 0, c;
        const char *parts[3];
        char want[3][48];

        cases[n].x = kmac_msg_short; cases[n].xlen = 4;
        cases[n].custom = ""; parts[n] = "custom-empty"; n++;
        cases[n].x = kmac_msg_short; cases[n].xlen = 4;
        cases[n].custom = kmac_custom_text; parts[n] = "custom-text"; n++;
        if (strcmp(name, "KMAC-128") == 0) {
            cases[n].x = msg; cases[n].xlen = 200;
            cases[n].custom = kmac_custom_text; parts[n] = "long-custom-text"; n++;
        } else {
            cases[n].x = msg; cases[n].xlen = 200;
            cases[n].custom = ""; parts[n] = "long-custom-empty"; n++;
        }
        for (c = 0; c < n; c++)
            snprintf(want[c], sizeof(want[c]), "%s.nist", parts[c]);

        for (c = 0; c < n; c++) {
            EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);
            OSSL_PARAM a[2];
            const OSSL_PARAM *pp = NULL;

            if (cases[c].custom != NULL) {
                a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM,
                                                         (void *)cases[c].custom,
                                                         strlen(cases[c].custom));
                a[1] = OSSL_PARAM_construct_end();
                pp = a;
            }
            outl = 0;
            if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), pp) == 1) {
                printf("deflt%s.%s.init=1\n", label, parts[c]);
                if (EVP_MAC_update(k, cases[c].x, cases[c].xlen) == 1
                    && EVP_MAC_final(k, out, &outl, sizeof(out)) == 1) {
                    printf("deflt%s.%s.len=%zu\n", label, parts[c], outl);
                    rt_hex_w("defltkmac", want[c], out, outl);
                } else {
                    printf("deflt%s.%s.enclen=0\n", label, parts[c]);
                }
            } else {
                printf("deflt%s.%s.init=0\n", label, parts[c]);
            }
            EVP_MAC_CTX_free(k);
        }
    }

    /* The same message split at every boundary, and byte at a time: the collector, not the tag. */
    for (i = 0; i <= 4; i++) {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);

        outl = 0;
        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL) == 1
            && EVP_MAC_update(k, kmac_msg_short, i) == 1
            && EVP_MAC_update(k, kmac_msg_short + i, 4 - i) == 1
            && EVP_MAC_final(k, out, &outl, sizeof(out)) == 1) {
            snprintf(tag, sizeof(tag), "split%zu", i);
            rt_hex_w("defltkmac", tag, out, outl);
        } else {
            printf("deflt%s.split%zu=FAIL\n", label, i);
        }
        EVP_MAC_CTX_free(k);
    }
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);

        outl = 0;
        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL) == 1) {
            for (i = 0; i < 4; i++)
                EVP_MAC_update(k, kmac_msg_short + i, 1);
            if (EVP_MAC_final(k, out, &outl, sizeof(out)) == 1)
                rt_hex_w("defltkmac", "bytewise", out, outl);
            else
                printf("deflt%s.bytewise=FAIL\n", label);
        }
        EVP_MAC_CTX_free(k);
    }

    /* The two XOF spellings: `EVP_MAC_finalXOF`, and the `xof` control with a plain final. */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);

        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL) == 1) {
            set[0] = OSSL_PARAM_construct_octet_string(
                OSSL_MAC_PARAM_CUSTOM, (void *)kmac_custom_text, strlen(kmac_custom_text));
            set[1] = OSSL_PARAM_construct_end();
            EVP_MAC_CTX_set_params(k, set);
            if (EVP_MAC_update(k, kmac_msg_short, 4) == 1) {
                memset(out, 0, sizeof(out));
                printf("deflt%s.xof.finalxof=%d\n", label,
                       EVP_MAC_finalXOF(k, out, outbytes));
                rt_hex_w("defltkmac", "xof.finalxof", out, outbytes);
            }
        }
        EVP_MAC_CTX_free(k);
    }
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);

        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL) == 1) {
            set[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &one);
            set[1] = OSSL_PARAM_construct_end();
            printf("deflt%s.xof.ctrl=%d\n", label, EVP_MAC_CTX_set_params(k, set));
            if (EVP_MAC_update(k, kmac_msg_short, 4) == 1) {
                outl = 0;
                if (EVP_MAC_final(k, out, &outl, sizeof(out)) == 1)
                    rt_hex_w("defltkmac", "xof.ctrl", out, outl);
                else
                    printf("deflt%s.xof.ctrl.final=0\n", label);
            }
        }
        EVP_MAC_CTX_free(k);
    }
    /* A second `xof` read on the same context must keep answering 1 — the flag is sticky. */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);

        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL) == 1) {
            set[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &one);
            set[1] = OSSL_PARAM_construct_end();
            EVP_MAC_CTX_set_params(k, set);
            EVP_MAC_CTX_set_params(k, set);
            if (EVP_MAC_update(k, kmac_msg_short, 4) == 1) {
                outl = 0;
                if (EVP_MAC_final(k, out, &outl, sizeof(out)) == 1)
                    rt_hex_w("defltkmac", "xof.repeat", out, outl);
            }
        }
        EVP_MAC_CTX_free(k);
    }
    /* `xof` back to zero after it was set: the flag is a plain assignment, not a one-way latch. */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);
        int zero = 0;

        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL) == 1) {
            set[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &one);
            set[1] = OSSL_PARAM_construct_end();
            EVP_MAC_CTX_set_params(k, set);
            set[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &zero);
            printf("deflt%s.xof.zero=%d\n", label, EVP_MAC_CTX_set_params(k, set));
            if (EVP_MAC_update(k, kmac_msg_short, 4) == 1) {
                outl = 0;
                if (EVP_MAC_final(k, out, &outl, sizeof(out)) == 1)
                    rt_hex_w("defltkmac", "xof.zero", out, outl);
            }
        }
        EVP_MAC_CTX_free(k);
    }

    /*
     * `size` after `init`. The encoded length is written by `final`, so this changes the tag -- and it
     * changes what `EVP_MAC_CTX_get_mac_size` answers, which is what a caller sizes its buffer from.
     */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);
        size_t want = outbytes / 2;

        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL) == 1) {
            set[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &want);
            set[1] = OSSL_PARAM_construct_end();
            printf("deflt%s.size.afterinit=%d\n", label, EVP_MAC_CTX_set_params(k, set));
            printf("deflt%s.size.macsize=%zu\n", label, EVP_MAC_CTX_get_mac_size(k));
            if (EVP_MAC_update(k, kmac_msg_short, 4) == 1) {
                outl = 0;
                if (EVP_MAC_final(k, out, &outl, sizeof(out)) == 1) {
                    printf("deflt%s.size.len=%zu\n", label, outl);
                    rt_hex_w("defltkmac", "size.half", out, outl);
                } else {
                    printf("deflt%s.size.enclen=0\n", label);
                }
            }
        }
        EVP_MAC_CTX_free(k);
    }

    /* The `size` cap, one past `KMAC_MAX_OUTPUT_LEN` = `0xFFFFFF / 8`. */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);
        size_t over = 0xFFFFFF / 8 + 1;
        size_t at = 0xFFFFFF / 8;
        OSSL_PARAM p[2];

        EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL);
        ERR_clear_error();
        p[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &over);
        p[1] = OSSL_PARAM_construct_end();
        printf("deflt%s.size.over=%d\n", label, EVP_MAC_CTX_set_params(k, p));
        rt_errq("kmac_size_over");
        /* The cap itself is accepted, and a refusal leaves the *previous* length in place. */
        ERR_clear_error();
        p[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &at);
        printf("deflt%s.size.atcap=%d\n", label, EVP_MAC_CTX_set_params(k, p));
        rt_errq("kmac_size_atcap");
        printf("deflt%s.size.atcap.macsize=%zu\n", label, EVP_MAC_CTX_get_mac_size(k));
        EVP_MAC_CTX_free(k);
    }

    /* A final buffer one byte short: refused at the EVP layer, before the row. */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);

        EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL);
        EVP_MAC_update(k, kmac_msg_short, 4);
        ERR_clear_error();
        outl = 0;
        printf("deflt%s.final.short=%d\n", label, EVP_MAC_final(k, out, &outl, outbytes - 1));
        printf("deflt%s.final.short.outl=%zu\n", label, outl);
        rt_errq("kmac_final_short");
        EVP_MAC_CTX_free(k);
    }

    /* The key-length bounds: three below the minimum, the minimum, the maximum, one above. */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);
        unsigned char big[520];

        memset(big, 0xA5, sizeof(big));
        ERR_clear_error();
        printf("deflt%s.key3=%d\n", label, EVP_MAC_init(k, kmac_key, 3, NULL));
        rt_errq("kmac_key3");
        ERR_clear_error();
        printf("deflt%s.key4=%d\n", label, EVP_MAC_init(k, kmac_key, 4, NULL));
        rt_errq("kmac_key4");
        ERR_clear_error();
        printf("deflt%s.key512=%d\n", label, EVP_MAC_init(k, big, 512, NULL));
        rt_errq("kmac_key512");
        ERR_clear_error();
        printf("deflt%s.key513=%d\n", label, EVP_MAC_init(k, big, 513, NULL));
        rt_errq("kmac_key513");
        /* A NULL key after one was stored is *not* a refusal: `key_len != 0`. */
        ERR_clear_error();
        printf("deflt%s.keynull=%d\n", label, EVP_MAC_init(k, NULL, 0, NULL));
        rt_errq("kmac_keynull");
        EVP_MAC_CTX_free(k);
    }

    /* A context that never had a key. */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);

        ERR_clear_error();
        printf("deflt%s.nokey=%d\n", label, EVP_MAC_init(k, NULL, 0, NULL));
        rt_errq("kmac_nokey");
        EVP_MAC_CTX_free(k);
    }

    /* A key delivered through the parameter array, then a keyless init that reuses it. */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);

        set[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)kmac_key,
                                                   sizeof(kmac_key));
        set[1] = OSSL_PARAM_construct_end();
        printf("deflt%s.pkey.set=%d\n", label, EVP_MAC_CTX_set_params(k, set));
        outl = 0;
        if (EVP_MAC_init(k, NULL, 0, NULL) == 1
            && EVP_MAC_update(k, kmac_msg_short, 4) == 1
            && EVP_MAC_final(k, out, &outl, sizeof(out)) == 1) {
            printf("deflt%s.pkey.len=%zu\n", label, outl);
            rt_hex_w("defltkmac", "pkey", out, outl);
        } else {
            printf("deflt%s.pkey=FAIL\n", label);
        }
        EVP_MAC_CTX_free(k);
    }

    /*
     * The customisation string's arms: set twice before init (last wins), set *after* init (inert),
     * the wrong type, over the cap, and at the cap. The second is the one that matters -- it is the
     * authority's own stated rule and the reason the NIST vectors above pass the descriptor to
     * `EVP_MAC_init`.
     */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);
        unsigned char big[600];
        OSSL_PARAM a[2], pp[2];
        size_t outl2 = 0;

        memset(big, 0x5A, sizeof(big));

        /* Two customs offered to one init: the decoder raises on the second, so the first wins. */
        pp[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM,
                                                  (void *)kmac_custom_text,
                                                  strlen(kmac_custom_text));
        pp[1] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)"first", 5);
        a[1] = OSSL_PARAM_construct_end();
        printf("deflt%s.custom.after.set=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_custom_after");
        /* The post-init set is accepted and changes nothing: the tag is the init-time one. */
        printf("deflt%s.custom.after.init=%d\n", label,
               EVP_MAC_init(k, kmac_key, sizeof(kmac_key), pp));
        a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)"second", 6);
        printf("deflt%s.custom.after.second=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        outl2 = 0;
        if (EVP_MAC_update(k, kmac_msg_short, 4) == 1
            && EVP_MAC_final(k, out, &outl2, sizeof(out)) == 1)
            rt_hex_w("defltkmac", "custom.after", out, outl2);
        EVP_MAC_CTX_free(k);

        /* The wrong type, and the two length boundaries. */
        k = EVP_MAC_CTX_new(mac);
        EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL);

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_CUSTOM, &one);
        printf("deflt%s.custom.type=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_custom_type");

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, big, 513);
        printf("deflt%s.custom.over=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_custom_over");
        /* 512 is the cap itself and is accepted. */
        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, big, 512);
        printf("deflt%s.custom.atcap=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_custom_atcap");
        EVP_MAC_CTX_free(k);

        /* A 512-byte custom supplied to the init itself, which is the accepted form. */
        k = EVP_MAC_CTX_new(mac);
        pp[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, big, 512);
        outl2 = 0;
        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), pp) == 1
            && EVP_MAC_update(k, kmac_msg_short, 4) == 1
            && EVP_MAC_final(k, out, &outl2, sizeof(out)) == 1)
            rt_hex_w("defltkmac", "custom.atcap.tag", out, outl2);
        else
            printf("deflt%s.custom.atcap.tag=FAIL\n", label);
        EVP_MAC_CTX_free(k);
    }

    /*
     * The row's digest cannot be changed. `hmac_prov.c` re-fetches on a `digest` key; this unit has no
     * such arm and the generated decoder has no such key, so the parameter is skipped and the tag is
     * the one the row would have produced anyway. The arm prints both tags.
     */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);
        OSSL_PARAM a[2];

        a[0] = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_DIGEST, (void *)"SHA256", 0);
        a[1] = OSSL_PARAM_construct_end();
        printf("deflt%s.set.digest=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        outl = 0;
        if (EVP_MAC_init(k, kmac_key, sizeof(kmac_key), NULL) == 1
            && EVP_MAC_update(k, kmac_msg_short, 4) == 1
            && EVP_MAC_final(k, out, &outl, sizeof(out)) == 1)
            rt_hex_w("defltkmac", "set.digest.tag", out, outl);
        else
            printf("deflt%s.set.digest.tag=FAIL\n", label);
        EVP_MAC_CTX_free(k);
    }
    /* The `digest` key is not in the settable list either, which is the same fact from the table. */
    {
        const OSSL_PARAM *p = EVP_MAC_CTX_settable_params(ctx);
        int found = 0;

        for (; p != NULL && p->key != NULL; p++)
            if (strcmp(p->key, OSSL_ALG_PARAM_DIGEST) == 0)
                found = 1;
        printf("deflt%s.settable.digest=%d\n", label, found);
    }

    /*
     * The decoder's repeated-parameter sites, one arm each: `xof`, `size`, `key`, `custom` on the
     * setter and `size`, `block-size` on the getter. The authority raises at the *decoder's*
     * coordinate, so the probe prints the queue and the court compares the coordinate rather than the
     * return value alone.
     */
    {
        EVP_MAC_CTX *k = EVP_MAC_CTX_new(mac);
        size_t sz = 0;
        int x = 0, bsz = 0;
        OSSL_PARAM a[3];

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &x);
        a[1] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &x);
        a[2] = OSSL_PARAM_construct_end();
        printf("deflt%s.rep.xof=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_rep_xof");

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        a[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        a[2] = OSSL_PARAM_construct_end();
        printf("deflt%s.rep.size=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_rep_size");

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)kmac_key,
                                                 sizeof(kmac_key));
        a[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)kmac_key,
                                                 sizeof(kmac_key));
        a[2] = OSSL_PARAM_construct_end();
        printf("deflt%s.rep.key=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_rep_key");

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)"a", 1);
        a[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)"b", 1);
        a[2] = OSSL_PARAM_construct_end();
        printf("deflt%s.rep.custom=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_rep_custom");

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        a[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        a[2] = OSSL_PARAM_construct_end();
        printf("deflt%s.rep.getsize=%d\n", label, EVP_MAC_CTX_get_params(k, a));
        rt_errq("kmac_rep_getsize");

        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_BLOCK_SIZE, &bsz);
        a[1] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_BLOCK_SIZE, &bsz);
        a[2] = OSSL_PARAM_construct_end();
        printf("deflt%s.rep.getbsize=%d\n", label, EVP_MAC_CTX_get_params(k, a));
        rt_errq("kmac_rep_getbsize");

        /* A `key` of the wrong type is a bare 0 with **no** raise, unlike every length refusal. */
        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_KEY, &x);
        a[1] = OSSL_PARAM_construct_end();
        printf("deflt%s.set.keytype=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_set_keytype");

        /* An `xof` of the wrong type is refused by the params layer, which raises its own error. */
        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_XOF, &sz);
        a[1] = OSSL_PARAM_construct_end();
        printf("deflt%s.set.xoftype=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_set_xoftype");

        /* A `size` of the wrong type, likewise. */
        ERR_clear_error();
        a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_SIZE, &x);
        a[1] = OSSL_PARAM_construct_end();
        printf("deflt%s.set.sizetype=%d\n", label, EVP_MAC_CTX_set_params(k, a));
        rt_errq("kmac_set_sizetype");

        EVP_MAC_CTX_free(k);
    }

    /* The duplicate, mid-message. */
    {
        EVP_MAC_CTX *a0 = EVP_MAC_CTX_new(mac);
        EVP_MAC_CTX *b0;
        int ok_copy, ok_orig;
        size_t outl2 = 0;

        printf("deflt%s.dup.init=%d\n", label,
               EVP_MAC_init(a0, kmac_key, sizeof(kmac_key), NULL));
        printf("deflt%s.dup.update=%d\n", label, EVP_MAC_update(a0, kmac_msg_short, 2));
        b0 = EVP_MAC_CTX_dup(a0);
        printf("deflt%s.dup.made=%d\n", label, b0 != NULL);
        if (b0 != NULL) {
            printf("deflt%s.dup.copy.update=%d\n", label,
                   EVP_MAC_update(b0, kmac_msg_short + 2, 2));
            outl = 0;
            outl2 = 0;
            ok_copy = EVP_MAC_final(b0, out, &outl, sizeof(out));
            printf("deflt%s.dup.copy.final=%d\n", label, ok_copy);
            if (ok_copy)
                rt_hex_w("defltkmac", "dup.copy", out, outl);
            ok_orig = EVP_MAC_final(a0, out, &outl2, sizeof(out));
            printf("deflt%s.dup.orig.final=%d\n", label, ok_orig);
            if (ok_orig)
                rt_hex_w("defltkmac", "dup.orig", out, outl2);
            EVP_MAC_CTX_free(b0);
        }
        EVP_MAC_CTX_free(a0);
    }

    /* The digest's own size, which is where `out_len`'s default comes from. */
    printf("deflt%s.defaultsize=%zu\n", label, outbytes);
    printf("deflt%s.defaultblock=%zu\n", label, blocksize);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static void rt_deflt_kmac(void)
{
    rt_deflt_kmac_one("KMAC-128", "kmac128", "KMAC128", "2.16.840.1.101.3.4.2.19", 32, 168);
    rt_deflt_kmac_one("KMAC-256", "kmac256", "KMAC256", "2.16.840.1.101.3.4.2.20", 64, 136);
}

/*
 * The `ChaCha20` row -- the last cipher of 8.3, and the first one in this half whose primitive is
 * **perlasm-only in this profile** (`crypto/chacha/chacha_enc.c` is not compiled at all; see
 * `src/chacha.rs`).
 *
 * Six things are particular to it.
 *
 * **The row's block size is one byte.** `EVP_CIPHER_get_block_size` answers 1, which is what says
 * the row is a stream cipher to every caller that reasons about alignment, and it is why the update
 * and final are the *stream* generics with no padding. The `invariant` arm prints all three lengths.
 *
 * **`updated-iv` is generated, not stored.** The counter block is four little-endian words, and
 * `EVP_CIPHER_CTX_get_params(OSSL_CIPHER_PARAM_UPDATED_IV)` reproduces it — so it is read *before*
 * any data (where it must equal the IV that was set) and again after a block boundary, and the
 * pinned corpus supplies the expected second value: RFC 7539's `NextIV` is `01000000…`.
 *
 * **The key and IV lengths are checked, not set.** `chacha20_set_ctx_params` refuses any `keylen`
 * but 32 and any `ivlen` but 16, with `PROV_R_INVALID_KEY_LENGTH`/`PROV_R_INVALID_IV_LENGTH`, which
 * is why a row that publishes a two-key setter can change nothing through it. Both refusals and the
 * queues they leave are printed.
 *
 * **The counter carries across calls, and the partial block is held.** `ChaCha20_ctr32` advances
 * only `counter[0]`, so the row adds the block count itself, carries into `counter[1]`, and keeps the
 * remainder in `ctx->buf` with `partial_len`. The `split` arms are what observe that: a hundred bytes
 * then twenty-eight must equal a hundred and twenty-eight in one call, and the `updated-iv` between
 * the two calls must be the block boundary rather than the byte boundary.
 *
 * **A second `EVP_EncryptInit_ex` with no IV resumes rather than restarts**, because
 * `chacha20_initiv` collects the counter only when `iv_set` is already true. That is the row's most
 * easily-lost behaviour and it is the `resume` arm.
 *
 * **`dupctx` is a whole-context copy, `hw` included.** `EVP_CIPHER_CTX_copy` mid-partial-block must
 * give two contexts that continue identically — which only works if the copy carries the counter,
 * the held block and the hw pointer that reached them.
 */
static void rt_deflt_chacha20(void)
{
    static const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char zero_iv[16] = { 0 };
    unsigned char in[400], out[400], dec[400], iv[16], got[16];
    unsigned char iv_copy[16];
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "ChaCha20", NULL);
    EVP_CIPHER_CTX *ctx, *cp;
    OSSL_PARAM p[2];
    size_t i, outl;
    int l1, l2;
    size_t ivl = sizeof(got);

    printf("chacha.fetched=%d\n", cipher != NULL);
    if (cipher == NULL)
        return;
    for (i = 0; i < sizeof(in); i++)
        in[i] = (unsigned char)i;

    /*
     * The three lengths and the two parameter lists. A block size of one is the contract every
     * alignment-reasoning caller depends on, and the lists are the row's own: three gettable keys
     * with `updated-iv` an octet string, and two settable ones that exist to be refused.
     */
    printf("chacha.keylen=%d\n", EVP_CIPHER_get_key_length(cipher));
    printf("chacha.ivlen=%d\n", EVP_CIPHER_get_iv_length(cipher));
    printf("chacha.block=%d\n", EVP_CIPHER_get_block_size(cipher));
    rt_param_list("chacha", "x", "gp", EVP_CIPHER_gettable_params(cipher));
    /*
     * **A cipher-less context faults the authority, so this arm prints the boundary rather than
     * calling it.** `EVP_CIPHER_CTX_gettable_params`'s guard is
     * `if (cctx != NULL && cctx->cipher->gettable_ctx_params != NULL)`, which dereferences
     * `cctx->cipher` without checking it -- measured: a fresh `EVP_CIPHER_CTX_new()` segfaults. A
     * probe cannot compare a crash, so the marker is printed on both sides and the boundary is
     * recorded as `D-CIPHERCTX-NOALG-1` in `docs/SECURITY_DIVERGENCE_POLICY.md`.
     */
    printf("chacha.x.cgp.unset=NOT_MEASURED_AUTHORITY_FAULTS\n");
    /* The two ctx-level lists are read *after* an init, which is the only reachable way. */
    {
        EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();

        printf("chacha.x.cgp.init=%d\n", EVP_CipherInit_ex(c, cipher, NULL, NULL, NULL, 1));
        rt_param_list("chacha", "x", "cgp", EVP_CIPHER_CTX_gettable_params(c));
        rt_param_list("chacha", "x", "csp", EVP_CIPHER_CTX_settable_params(c));
        EVP_CIPHER_CTX_free(c);
    }

    /*
     * **RFC 7539 A.1 Test Vector 1.** An all-zero key, an all-zero counter block and sixty-four zero
     * bytes in gives the standard's first keystream block out; `NextIV` is the counter block after
     * one block, which is what `updated-iv` must reproduce.
     */
    {
        static const unsigned char v1[64] = {
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
        };
        static const unsigned char zero_key[32] = { 0 };
        unsigned char zero[64] = { 0 };

        ctx = EVP_CIPHER_CTX_new();
        printf("chacha.v1.init=%d\n",
               EVP_EncryptInit_ex(ctx, cipher, NULL, zero_key, zero_iv));
        outl = 0;
        printf("chacha.v1.update=%d\n", EVP_EncryptUpdate(ctx, out, &l1, zero, 64));
        outl = (size_t)l1;
        printf("chacha.v1.final=%d\n", EVP_EncryptFinal_ex(ctx, out + outl, &l2));
        outl += (size_t)l2;
        printf("chacha.v1.len=%zu\n", outl);
        rt_hex("chacha.v1.out", out, outl);
        printf("chacha.v1.matches=%d\n", outl == 64 && memcmp(out, v1, 64) == 0);

        /* `NextIV` == `updated-iv` after exactly one block. */
        memset(got, 0, sizeof(got));
        ivl = sizeof(got);
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, ivl);
        p[1] = OSSL_PARAM_construct_end();
        printf("chacha.v1.updated=%d\n", EVP_CIPHER_CTX_get_params(ctx, p));
        rt_hex("chacha.v1.nextiv", got, 16);
        EVP_CIPHER_CTX_free(ctx);
    }

    /* `updated-iv` before any data must be the IV that was set, and the round trip must hold. */
    for (i = 0; i < 16; i++)
        iv[i] = (unsigned char)(0xa0 + i);
    ctx = EVP_CIPHER_CTX_new();
    printf("chacha.rt.init=%d\n", EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv));
    printf("chacha.rt.ctx.keylen=%d\n", EVP_CIPHER_CTX_get_key_length(ctx));
    printf("chacha.rt.ctx.ivlen=%d\n", EVP_CIPHER_CTX_get_iv_length(ctx));
    printf("chacha.rt.ctx.block=%d\n", EVP_CIPHER_CTX_get_block_size(ctx));
    memset(got, 0, sizeof(got));
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, sizeof(got));
    p[1] = OSSL_PARAM_construct_end();
    printf("chacha.rt.updated.before=%d\n", EVP_CIPHER_CTX_get_params(ctx, p));
    rt_hex("chacha.rt.updated.before.iv", got, 16);

    /*
     * 128 bytes in two calls: 100 then 28. The boundary falls inside the second block, so the first
     * call holds 36 bytes of partial block and the second must consume it before generating.
     */
    outl = 0;
    printf("chacha.rt.u1=%d\n", EVP_EncryptUpdate(ctx, out, &l1, in, 100));
    printf("chacha.rt.u1.len=%d\n", l1);
    outl += (size_t)l1;
    memset(got, 0, sizeof(got));
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, sizeof(got));
    printf("chacha.rt.updated.mid=%d\n", EVP_CIPHER_CTX_get_params(ctx, p));
    rt_hex("chacha.rt.updated.mid.iv", got, 16);

    /* The `updated-iv` setter is not published: only keylen and ivlen are, and both are refusals. */
    {
        unsigned char bad[16] = { 0 };

        p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, bad, 16);
        p[1] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        printf("chacha.rt.updated.set=%d\n", EVP_CIPHER_CTX_set_params(ctx, p));
        rt_errq("chacha_updated_set");
    }

    printf("chacha.rt.u2=%d\n", EVP_EncryptUpdate(ctx, out + outl, &l1, in + 100, 28));
    outl += (size_t)l1;
    printf("chacha.rt.final=%d\n", EVP_EncryptFinal_ex(ctx, out + outl, &l2));
    outl += (size_t)l2;
    printf("chacha.rt.len=%zu\n", outl);
    rt_hex("chacha.rt.enc", out, outl);
    memset(got, 0, sizeof(got));
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, sizeof(got));
    EVP_CIPHER_CTX_get_params(ctx, p);
    rt_hex("chacha.rt.updated.after.iv", got, 16);
    EVP_CIPHER_CTX_free(ctx);

    /*
     * The same 128 bytes in **one** call must produce the same ciphertext and the same final
     * `updated-iv`. This is the arm that a partial-block bug breaks and nothing else does.
     */
    {
        EVP_CIPHER_CTX *one = EVP_CIPHER_CTX_new();
        unsigned char one_out[400];
        size_t one_len = 0;

        EVP_EncryptInit_ex(one, cipher, NULL, key, iv);
        printf("chacha.whole.u=%d\n", EVP_EncryptUpdate(one, one_out, &l1, in, 128));
        one_len += (size_t)l1;
        printf("chacha.whole.final=%d\n", EVP_EncryptFinal_ex(one, one_out + one_len, &l2));
        one_len += (size_t)l2;
        printf("chacha.whole.len=%zu\n", one_len);
        rt_hex("chacha.whole.enc", one_out, one_len);
        printf("chacha.whole.agrees=%d\n",
               one_len == outl && memcmp(one_out, out, outl) == 0);
        memset(got, 0, sizeof(got));
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, sizeof(got));
        EVP_CIPHER_CTX_get_params(one, p);
        rt_hex("chacha.whole.updated.iv", got, 16);
        EVP_CIPHER_CTX_free(one);
    }

    /* The decrypt twin, on the two-call ciphertext, must return the plaintext. */
    ctx = EVP_CIPHER_CTX_new();
    printf("chacha.dec.init=%d\n", EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv));
    {
        size_t dl = 0;

        printf("chacha.dec.u1=%d\n", EVP_DecryptUpdate(ctx, dec, &l1, out, 100));
        dl += (size_t)l1;
        printf("chacha.dec.u2=%d\n", EVP_DecryptUpdate(ctx, dec + dl, &l1, out + 100, 28));
        dl += (size_t)l1;
        printf("chacha.dec.final=%d\n", EVP_DecryptFinal_ex(ctx, dec + dl, &l2));
        dl += (size_t)l2;
        printf("chacha.dec.len=%zu\n", dl);
        printf("chacha.dec.roundtrip=%d\n", dl == 128 && memcmp(dec, in, 128) == 0);
    }
    EVP_CIPHER_CTX_free(ctx);

    /*
     * **A re-init that does not name a cipher resumes; one that names it does not.**
     *
     * `EVP_EncryptInit_ex(ctx, NULL, ...)` keeps the cipher *and* its `algctx`, so the counter block
     * survives and the second half of a 128-byte message is the tail of the one-call ciphertext.
     * That is the form `chacha20_initiv`'s `iv_set` conditional is for.
     *
     * `EVP_EncryptInit_ex(ctx, cipher, ...)` was measured and **does not** resume: the counter block
     * comes back all zero and the following update yields nothing, so naming the cipher again
     * replaces the algorithm context rather than re-entering the row. Both forms are printed,
     * because the difference is the whole observable and a probe that only did the first would have
     * recorded the wrong rule.
     */
    {
        EVP_CIPHER_CTX *res = EVP_CIPHER_CTX_new();
        unsigned char half[400];
        size_t hl = 0;

        printf("chacha.resume.init=%d\n", EVP_EncryptInit_ex(res, cipher, NULL, key, iv));
        EVP_EncryptUpdate(res, half, &l1, in, 64);
        hl += (size_t)l1;
        printf("chacha.resume.reinit=%d\n", EVP_EncryptInit_ex(res, NULL, NULL, NULL, NULL));
        EVP_EncryptUpdate(res, half + hl, &l1, in + 64, 64);
        hl += (size_t)l1;
        EVP_EncryptFinal_ex(res, half + hl, &l2);
        hl += (size_t)l2;
        printf("chacha.resume.len=%zu\n", hl);
        rt_hex("chacha.resume.enc", half, hl);
        printf("chacha.resume.agrees=%d\n", hl == 128 && memcmp(half, out, 128) == 0);
        memset(got, 0, sizeof(got));
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, sizeof(got));
        EVP_CIPHER_CTX_get_params(res, p);
        rt_hex("chacha.resume.updated.iv", got, 16);
        EVP_CIPHER_CTX_free(res);
    }
    {
        EVP_CIPHER_CTX *res = EVP_CIPHER_CTX_new();
        unsigned char half[400];
        size_t hl = 0;

        EVP_EncryptInit_ex(res, cipher, NULL, key, iv);
        EVP_EncryptUpdate(res, half, &l1, in, 64);
        hl += (size_t)l1;
        printf("chacha.recipher.reinit=%d\n",
               EVP_EncryptInit_ex(res, cipher, NULL, NULL, NULL));
        printf("chacha.recipher.u=%d\n", EVP_EncryptUpdate(res, half + hl, &l1, in + 64, 64));
        hl += (size_t)l1;
        printf("chacha.recipher.final=%d\n", EVP_EncryptFinal_ex(res, half + hl, &l2));
        hl += (size_t)l2;
        printf("chacha.recipher.len=%zu\n", hl);
        memset(got, 0, sizeof(got));
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, sizeof(got));
        EVP_CIPHER_CTX_get_params(res, p);
        rt_hex("chacha.recipher.updated.iv", got, 16);
        EVP_CIPHER_CTX_free(res);
    }

    /*
     * **`dupctx` is a whole-context copy, and the comparison window is the *continuation*.**
     *
     * The duplicate is taken after 70 bytes, so it holds no copy of the first 70 output bytes — a
     * comparison of the two whole buffers would read uninitialised memory in the duplicate's (the
     * first version of this arm did exactly that, and its `agrees=0` was the probe's bug rather than
     * a defect). What must agree is `a`'s continuation against `b`'s, byte for byte, and `a`'s whole
     * output against the one-call ciphertext above.
     */
    {
        EVP_CIPHER_CTX *a = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *b = EVP_CIPHER_CTX_new();
        unsigned char oa[400], ob[400];
        size_t la = 0, lb = 0;
        int first;

        EVP_EncryptInit_ex(a, cipher, NULL, key, iv);
        EVP_EncryptUpdate(a, oa, &l1, in, 70);
        la += (size_t)l1;
        first = l1;
        printf("chacha.dup.first=%d\n", first);
        printf("chacha.dup.copy=%d\n", EVP_CIPHER_CTX_copy(b, a));
        /* `a` continues, and `b` continues with the same bytes: the two must agree from 70 on. */
        EVP_EncryptUpdate(a, oa + la, &l1, in + 70, 58);
        la += (size_t)l1;
        EVP_EncryptUpdate(b, ob, &l1, in + 70, 58);
        lb += (size_t)l1;
        EVP_EncryptFinal_ex(a, oa + la, &l2);
        la += (size_t)l2;
        EVP_EncryptFinal_ex(b, ob + lb, &l2);
        lb += (size_t)l2;
        printf("chacha.dup.la=%zu\n", la);
        printf("chacha.dup.lb=%zu\n", lb);
        printf("chacha.dup.cont=%zu\n", la - (size_t)first);
        printf("chacha.dup.agrees=%d\n",
               lb == la - (size_t)first
                   && memcmp(oa + (size_t)first, ob, lb) == 0);
        printf("chacha.dup.whole=%d\n", la == 128 && memcmp(oa, out, 128) == 0);
        EVP_CIPHER_CTX_free(a);
        EVP_CIPHER_CTX_free(b);
    }

    /*
     * **The two length keys are refusals.** `keylen` of 16 and `ivlen` of 8 are each refused with the
     * row's own reason, and the correct values are accepted — which is why the row publishes a setter
     * that can change nothing.
     */
    {
        size_t bad_keylen = 16, good_keylen = 32, bad_ivlen = 8, good_ivlen = 16;

        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

        ERR_clear_error();
        p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &bad_keylen);
        p[1] = OSSL_PARAM_construct_end();
        printf("chacha.set.keylen.bad=%d\n", EVP_CIPHER_CTX_set_params(ctx, p));
        rt_errq("chacha_keylen_bad");

        ERR_clear_error();
        p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &good_keylen);
        printf("chacha.set.keylen.good=%d\n", EVP_CIPHER_CTX_set_params(ctx, p));
        rt_errq("chacha_keylen_good");

        ERR_clear_error();
        p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &bad_ivlen);
        printf("chacha.set.ivlen.bad=%d\n", EVP_CIPHER_CTX_set_params(ctx, p));
        rt_errq("chacha_ivlen_bad");

        ERR_clear_error();
        p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &good_ivlen);
        printf("chacha.set.ivlen.good=%d\n", EVP_CIPHER_CTX_set_params(ctx, p));
        rt_errq("chacha_ivlen_good");

        /* A wrong *type* is refused by the params layer, which raises a `CRYPTO` error instead. */
        ERR_clear_error();
        p[0] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_KEYLEN, &l1);
        printf("chacha.set.keylen.type=%d\n", EVP_CIPHER_CTX_set_params(ctx, p));
        rt_errq("chacha_keylen_type");

        /* An unknown key is ignored: the row's decoder locates by name and finds nothing. */
        ERR_clear_error();
        p[0] = OSSL_PARAM_construct_size_t("nonesuch", &good_keylen);
        printf("chacha.set.unknown=%d\n", EVP_CIPHER_CTX_set_params(ctx, p));
        rt_errq("chacha_set_unknown");
        EVP_CIPHER_CTX_free(ctx);
    }

    /* A one-shot `EVP_Cipher` on a 200-byte message, and the straddling-tail case at a block edge. */
    for (i = 0; i <= 130; i += 65) {
        EVP_CIPHER_CTX *one = EVP_CIPHER_CTX_new();
        unsigned char o[400];
        size_t olen = 0;

        EVP_EncryptInit_ex(one, cipher, NULL, key, iv);
        printf("chacha.sz%zu.u=%d\n", i, EVP_EncryptUpdate(one, o, &l1, in, i));
        olen += (size_t)l1;
        printf("chacha.sz%zu.final=%d\n", i, EVP_EncryptFinal_ex(one, o + olen, &l2));
        olen += (size_t)l2;
        printf("chacha.sz%zu.len=%zu\n", i, olen);
        rt_hex_w("chacha", i == 0 ? "sz0.enc" : "sz65.enc", o, olen);
        memset(got, 0, sizeof(got));
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, sizeof(got));
        EVP_CIPHER_CTX_get_params(one, p);
        rt_hex_w("chacha", i == 0 ? "sz0.iv" : "sz65.iv", got, 16);
        EVP_CIPHER_CTX_free(one);
    }

    /*
     * The counter's second word. `ChaCha20_ctr32` advances only `counter[0]`; the row carries into
     * `counter[1]` itself. Setting the first word to `0xffffffff` puts the very next block on the
     * carry, which is the one input that distinguishes a row that carries from one that does not.
     */
    for (i = 0; i < 16; i++)
        iv_copy[i] = 0;
    iv_copy[0] = 0xff;
    iv_copy[1] = 0xff;
    iv_copy[2] = 0xff;
    iv_copy[3] = 0xff;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv_copy);
    outl = 0;
    EVP_EncryptUpdate(ctx, out, &l1, in, 128);
    outl += (size_t)l1;
    EVP_EncryptFinal_ex(ctx, out + outl, &l2);
    outl += (size_t)l2;
    printf("chacha.carry.len=%zu\n", outl);
    rt_hex("chacha.carry.enc", out, outl);
    memset(got, 0, sizeof(got));
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, got, sizeof(got));
    EVP_CIPHER_CTX_get_params(ctx, p);
    rt_hex("chacha.carry.iv", got, 16);
    EVP_CIPHER_CTX_free(ctx);

    /* The same 128 bytes under the pre-carry IV must differ, so the arm is not vacuous. */
    {
        unsigned char iv2[16];
        unsigned char other[400];
        size_t other_len = 0;

        memcpy(iv2, iv_copy, 16);
        iv2[0] = 0xfe;
        cp = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(cp, cipher, NULL, key, iv2);
        EVP_EncryptUpdate(cp, other, &l1, in, 128);
        other_len += (size_t)l1;
        EVP_EncryptFinal_ex(cp, other + other_len, &l2);
        other_len += (size_t)l2;
        printf("chacha.carry.differs=%d\n",
               other_len == outl && memcmp(other, out, outl) != 0);
        EVP_CIPHER_CTX_free(cp);
    }

    /* A NULL key on the first init: the generic init refuses, and the row's `initiv` is not reached. */
    {
        EVP_CIPHER_CTX *nk = EVP_CIPHER_CTX_new();

        ERR_clear_error();
        printf("chacha.nokey=%d\n", EVP_EncryptInit_ex(nk, cipher, NULL, NULL, iv));
        rt_errq("chacha_nokey");
        EVP_CIPHER_CTX_free(nk);
    }

    EVP_CIPHER_free(cipher);
}

/*
 * The `ChaCha20-Poly1305` row -- 8.3's last cipher, and the only landed row whose hw vtable's
 * `base.cipher` is NULL (`courts/layout/oracle-chacha20-poly1305-hw.c` prints all three base
 * members). It is also the only one that is a *stitching* of three already-landed constructions
 * rather than a new primitive, so what this arm has to reach is the **record shape**.
 *
 * Seven things are particular to it.
 *
 * **Two enciphering paths, and the TLS one is entered by a side effect.** Setting `tlsaad` leaves
 * `tls_payload_length` at the record's payload length, and the *next* `EVP_CipherUpdate` is then a
 * whole RFC 7905 record: the caller passes `payload + 16` and gets ciphertext plus tag back in one
 * call. Everywhere else the row is the ordinary incremental AEAD, and the `plain` arms are that
 * path. The two must not be confused, so both are exercised.
 *
 * **The TLS path's fast and slow arms are chosen by `plen <= 192`.** That threshold is the
 * `XOR128_HELPERS` arm's, and the two arms generate their keystream differently -- one call for
 * `128 + roundup(plen, 64)` bytes from block one, versus a single block for the poly1305 key and
 * then the whole payload through `ChaCha20_ctr32`. A payload of 32 octets takes the first and one
 * of 260 takes the second, so a transcription that got the threshold or either arm's origin wrong
 * cannot pass.
 *
 * **Thirteen bytes of AAD are hashed as sixteen.** `EVP_AEAD_TLS1_AAD_LEN` is 13 and
 * `chacha20_poly1305_tls_cipher` hashes `POLY1305_BLOCK_SIZE` bytes of `tls_aad`, so three zero
 * bytes go into the tag that the length block does not count. The `tlsaadpad` the control answers
 * is that sixteen, which is what makes the record sixteen octets longer than its plaintext.
 *
 * **The fixed IV can be installed two ways and they must agree.** The record layer's `else` branch
 * (`ssl/record/methods/tls1_meth.c:107`) hands the explicit IV straight to
 * `EVP_CipherInit_ex`, because ChaCha20-Poly1305's mode is 0 and not GCM's or CCM's; the
 * `EVP_CTRL_AEAD_SET_IV_FIXED` control is the other way. `initiv` pads the twelve octets into the
 * counter block either way, so the two records must be identical, and the arm prints whether they
 * are.
 *
 * **The tag has a direction.** `EVP_CTRL_AEAD_GET_TAG` on a decrypting context is
 * `PROV_R_TAG_NOT_SET`, and a non-NULL `SET_TAG` on an *encrypting* one is `PROV_R_TAG_NOT_NEEDED`
 * -- the two refusals are each other's mirror, and both queues are printed. A tag length outside
 * `1..=16` on either side is `PROV_R_INVALID_TAG_LENGTH`.
 *
 * **A zero-length update is a no-op that answers rather than a pass-through.** That is a separate
 * dispatch entry from the one-shot `cipher`, so `EVP_EncryptUpdate(ctx, out, &outl, in, 0)`
 * succeeds with `outl == 0` and leaves the poly1305 state alone.
 *
 * **The tag is checked silently.** A wrong tag or a wrong ciphertext is a plain `0` and the queue
 * is printed to say so, because the row raises nothing on that path -- which is an observable
 * difference from the GCM rows, not a detail.
 */
static void rt_deflt_chacha20_poly1305(void)
{
    /* RFC 8439's key and nonce, so this arm's records and the CT court's published vectors are the
     * same construction rather than two. */
    static const unsigned char key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const unsigned char nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };
    static const unsigned char aad13[13] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0x00
    };
    unsigned char in[512], ct[512], pt[512], tag[16], got[16], other[512];
    unsigned char tlsfixed[12];
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
    EVP_CIPHER_CTX *ctx;
    OSSL_PARAM p[2];
    size_t i, clen;
    int l1, l2, fin;

    printf("chachapoly.fetched=%d\n", cipher != NULL);
    if (cipher == NULL)
        return;
    for (i = 0; i < sizeof(in); i++)
        in[i] = (unsigned char)(i & 0xff);

    /* The lengths, the mode and the flags: a twelve-octet IV, a one-octet block and
     * `EVP_CIPH_FLAG_AEAD_CIPHER`. All four are what a caller reasons about. */
    printf("chachapoly.keylen=%d\n", EVP_CIPHER_get_key_length(cipher));
    printf("chachapoly.ivlen=%d\n", EVP_CIPHER_get_iv_length(cipher));
    printf("chachapoly.block=%d\n", EVP_CIPHER_get_block_size(cipher));
    printf("chachapoly.mode=%d\n", EVP_CIPHER_get_mode(cipher));
    printf("chachapoly.flags=%lu\n", (unsigned long)EVP_CIPHER_get_flags(cipher));
    rt_param_list("chachapoly", "x", "gp", EVP_CIPHER_gettable_params(cipher));

    /* The row's own context lists -- five gettable keys (`keylen`, `ivlen`, `taglen`, `tag`,
     * `tlsaadpad`) and five settable ones (`keylen`, `ivlen`, `tag`, `tlsaad`, `tlsivfixed`) -- and
     * the zero-length update, which is only reachable after a cipher is assigned. */
    {
        EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();

        if (c != NULL && EVP_CipherInit_ex(c, cipher, NULL, NULL, NULL, 1) == 1) {
            rt_param_list("chachapoly", "x", "cgp", EVP_CIPHER_CTX_gettable_params(c));
            rt_param_list("chachapoly", "x", "sgp", EVP_CIPHER_CTX_settable_params(c));

            ERR_clear_error();
            l1 = -999;
            printf("chachapoly.zeroupdate=%d\n", EVP_EncryptUpdate(c, other, &l1, in, 0));
            printf("chachapoly.zeroupdate.outl=%d\n", l1);
            rt_errq("chachapoly_zeroupdate");
        }
        if (c != NULL)
            EVP_CIPHER_CTX_free(c);
    }

    /* The setter's four one-key refusals, each with the queue that distinguishes them. */
    {
        static const char *const names[] = { "keylen33", "ivlen13", "tag0", "tag17" };
        size_t k;

        for (k = 0; k < sizeof(names) / sizeof(names[0]); k++) {
            EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
            unsigned char tagbuf[32];
            size_t sz;

            memset(tagbuf, 0, sizeof(tagbuf));
            memset(p, 0, sizeof(p));
            if (c == NULL || EVP_CipherInit_ex(c, cipher, NULL, NULL, NULL, 1) != 1) {
                printf("chachapoly.set.%s=noctx\n", names[k]);
                if (c != NULL)
                    EVP_CIPHER_CTX_free(c);
                continue;
            }
            ERR_clear_error();
            if (k == 0) {
                sz = 33;
                p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &sz);
            } else if (k == 1) {
                sz = 13;
                p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &sz);
            } else {
                sz = (k == 2) ? 0 : 17;
                p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tagbuf, sz);
            }
            p[1] = OSSL_PARAM_construct_end();
            printf("chachapoly.set.%s=%d\n", names[k], EVP_CIPHER_CTX_set_params(c, p));
            rt_errq(names[k]);
            EVP_CIPHER_CTX_free(c);
        }
    }

    /* The plain AEAD path, whole: 13 octets of AAD, 32 octets of text, the tag read back through
     * the classic control. */
    memset(ct, 0, sizeof(ct));
    memset(tag, 0, sizeof(tag));
    ctx = EVP_CIPHER_CTX_new();
    clen = 0;
    if (ctx == NULL
        || EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) != 1
        || EVP_EncryptInit_ex2(ctx, NULL, key, nonce, NULL) != 1) {
        printf("chachapoly.plain.enc=0\n");
    } else {
        printf("chachapoly.plain.aad=%d\n",
               EVP_EncryptUpdate(ctx, NULL, &l1, aad13, sizeof(aad13)));
        printf("chachapoly.plain.aad.outl=%d\n", l1);
        printf("chachapoly.plain.text=%d\n",
               EVP_EncryptUpdate(ctx, ct, &l1, in, 32));
        clen = (size_t)l1;
        printf("chachapoly.plain.text.outl=%d\n", l1);
        printf("chachapoly.plain.final=%d\n", EVP_EncryptFinal_ex(ctx, ct + clen, &l2));
        clen += (size_t)l2;
        printf("chachapoly.plain.final.outl=%d\n", l2);
        printf("chachapoly.plain.clen=%zu\n", clen);
        rt_hex("chachapoly.plain.ct", ct, clen);
        printf("chachapoly.plain.gettag=%d\n",
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
        rt_hex("chachapoly.plain.tag", tag, 16);

        /* `taglen` answers the context's own `tag_len`, which no `SET_TAG` has set, and `tlsaadpad`
         * is still zero because no record has been announced. */
        {
            size_t tl = 999, pad = 999;

            p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tl);
            p[1] = OSSL_PARAM_construct_end();
            printf("chachapoly.plain.cget.taglen=%d\n", EVP_CIPHER_CTX_get_params(ctx, p));
            printf("chachapoly.plain.taglen=%zu\n", tl);
            p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, &pad);
            printf("chachapoly.plain.cget.pad=%d\n", EVP_CIPHER_CTX_get_params(ctx, p));
            printf("chachapoly.plain.pad=%zu\n", pad);
        }

        /* Reading the tag from an *encrypting* context answers; the refusal is for the decrypting
         * side only. A buffer outside `1..=16` is the other refusal. */
        memset(got, 0, sizeof(got));
        printf("chachapoly.plain.encgettag16=%d\n",
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, got));
        rt_hex("chachapoly.plain.encgettag", got, 16);
        ERR_clear_error();
        printf("chachapoly.plain.encgettag0=%d\n",
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 0, got));
        rt_errq("chachapoly_encgettag0");
        ERR_clear_error();
        printf("chachapoly.plain.encgettag17=%d\n",
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 17, got));
        rt_errq("chachapoly_encgettag17");

        /* A non-NULL `SET_TAG` on an encrypting context. */
        ERR_clear_error();
        printf("chachapoly.plain.encsettag=%d\n",
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag));
        rt_errq("chachapoly_encsettag");
    }
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    /* The decrypting side: an acceptance, then a `GET_TAG` refusal on that side. */
    ERR_clear_error();
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_DecryptInit_ex2(ctx, cipher, NULL, NULL, NULL) != 1
        || EVP_DecryptInit_ex2(ctx, NULL, key, nonce, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) {
        printf("chachapoly.plain.dec=0\n");
    } else {
        memset(pt, 0, sizeof(pt));
        EVP_DecryptUpdate(ctx, NULL, &l1, aad13, sizeof(aad13));
        printf("chachapoly.plain.decupdate=%d\n",
               EVP_DecryptUpdate(ctx, pt, &l1, ct, (int)clen));
        printf("chachapoly.plain.decupdate.outl=%d\n", l1);
        printf("chachapoly.plain.decfinal=%d\n", EVP_DecryptFinal_ex(ctx, pt + l1, &l2));
        printf("chachapoly.plain.decfinal.outl=%d\n", l2);
        printf("chachapoly.plain.roundtrip=%d\n",
               l1 == 32 && memcmp(pt, in, 32) == 0);
        rt_hex("chachapoly.plain.pt", pt, 32);

        memset(got, 0, sizeof(got));
        ERR_clear_error();
        printf("chachapoly.plain.decgettag=%d\n",
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, got));
        rt_errq("chachapoly_decgettag");
    }
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    /* A flipped tag and a flipped ciphertext, each a silent refusal. */
    {
        int which;

        for (which = 0; which < 2; which++) {
            unsigned char bad[512];

            memcpy(bad, ct, clen);
            if (which == 0)
                tag[15] ^= 0x01;
            else
                bad[0] ^= 0x01;

            ERR_clear_error();
            ctx = EVP_CIPHER_CTX_new();
            memset(pt, 0, sizeof(pt));
            fin = 0;
            if (ctx != NULL
                && EVP_DecryptInit_ex2(ctx, cipher, NULL, NULL, NULL) == 1
                && EVP_DecryptInit_ex2(ctx, NULL, key, nonce, NULL) == 1
                && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1) {
                EVP_DecryptUpdate(ctx, NULL, &l1, aad13, sizeof(aad13));
                EVP_DecryptUpdate(ctx, pt, &l1, bad, (int)clen);
                fin = EVP_DecryptFinal_ex(ctx, pt + l1, &l2);
            }
            printf("chachapoly.bad.%s=%d\n", which == 0 ? "tag" : "ct", fin);
            rt_errq(which == 0 ? "chachapoly_badtag" : "chachapoly_badct");
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
        }
        tag[15] ^= 0x01;
    }

    /* The empty message: the tag comes from a final-only operation whose poly1305 input is a
     * different shape from any non-empty one. */
    {
        unsigned char etag[16];

        memset(etag, 0, sizeof(etag));
        ctx = EVP_CIPHER_CTX_new();
        if (ctx != NULL
            && EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) == 1
            && EVP_EncryptInit_ex2(ctx, NULL, key, nonce, NULL) == 1) {
            EVP_EncryptUpdate(ctx, NULL, &l1, aad13, sizeof(aad13));
            printf("chachapoly.empty.final=%d\n", EVP_EncryptFinal_ex(ctx, other, &l2));
            printf("chachapoly.empty.final.outl=%d\n", l2);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, etag);
            rt_hex("chachapoly.empty.tag", etag, 16);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);

        /* And the decrypting acceptance of a tag over no text at all. */
        ctx = EVP_CIPHER_CTX_new();
        if (ctx != NULL
            && EVP_DecryptInit_ex2(ctx, cipher, NULL, NULL, NULL) == 1
            && EVP_DecryptInit_ex2(ctx, NULL, key, nonce, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, etag) == 1) {
            EVP_DecryptUpdate(ctx, NULL, &l1, aad13, sizeof(aad13));
            printf("chachapoly.empty.decfinal=%d\n", EVP_DecryptFinal_ex(ctx, other, &l2));
            printf("chachapoly.empty.decfinal.outl=%d\n", l2);
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
    }

    /*
     * The TLS record, twice: a 32-octet payload (the fast arm, `plen <= 3 * CHACHA_BLK_SIZE`) and a
     * 260-octet payload (the slow arm). The AAD's last two octets carry the payload length
     * big-endian, and the caller passes `payload + 16` so the tag lands in the record.
     */
    {
        static const size_t payloads[2] = { 32, 260 };
        size_t w;

        for (w = 0; w < 2; w++) {
            size_t plen = payloads[w];
            char label[40], hexlabel[64];
            unsigned char rec[640], dec[640], aadlen[13], aaddec[13];
            EVP_CIPHER_CTX *ectx, *dctx;

            snprintf(label, sizeof(label), "chachapoly.tls%zu", plen);
            memcpy(aadlen, aad13, sizeof(aadlen));
            aadlen[11] = (unsigned char)(plen >> 8);
            aadlen[12] = (unsigned char)plen;
            /*
             * **The decrypting AAD's length field is the record length, not the payload length.**
             * TLS puts ciphertext-plus-tag in the record's length, and `tls_init` discounts the tag
             * itself -- it refuses anything shorter than a tag, subtracts `POLY1305_BLOCK_SIZE`, and
             * rewrites the two octets it will hash. Encrypting therefore announces `plen` and
             * decrypting announces `plen + 16`, which is why the two arrays differ.
             */
            memcpy(aaddec, aadlen, sizeof(aaddec));
            aaddec[11] = (unsigned char)((plen + 16) >> 8);
            aaddec[12] = (unsigned char)(plen + 16);
            memset(rec, 0, sizeof(rec));
            memset(dec, 0, sizeof(dec));

            ERR_clear_error();
            ectx = EVP_CIPHER_CTX_new();
            if (ectx == NULL || EVP_EncryptInit_ex2(ectx, cipher, key, nonce, NULL) != 1) {
                printf("%s.enc=0\n", label);
                if (ectx != NULL)
                    EVP_CIPHER_CTX_free(ectx);
                continue;
            }
            printf("%s.pad=%d\n", label,
                   EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_TLS1_AAD, 13, aadlen));
            ERR_clear_error();
            printf("%s.update=%d\n", label,
                   EVP_EncryptUpdate(ectx, rec, &l1, in, (int)(plen + 16)));
            printf("%s.update.outl=%d\n", label, l1);
            printf("%s.final=%d\n", label, EVP_EncryptFinal_ex(ectx, rec + l1, &l2));
            printf("%s.final.outl=%d\n", label, l2);
            snprintf(hexlabel, sizeof(hexlabel), "%s.ct", label);
            rt_hex(hexlabel, rec, plen + 16);
            EVP_CIPHER_CTX_free(ectx);

            /* The decrypting side, with the tag inside the record: this is the arm that proves
             * `tls_init` discounted the tag from the length it encoded in the AAD. */
            ERR_clear_error();
            dctx = EVP_CIPHER_CTX_new();
            if (dctx == NULL || EVP_DecryptInit_ex2(dctx, cipher, key, nonce, NULL) != 1) {
                printf("%s.dec=0\n", label);
                if (dctx != NULL)
                    EVP_CIPHER_CTX_free(dctx);
                continue;
            }
            EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_TLS1_AAD, 13, aaddec);
            printf("%s.decupdate=%d\n", label,
                   EVP_DecryptUpdate(dctx, dec, &l1, rec, (int)(plen + 16)));
            printf("%s.decupdate.outl=%d\n", label, l1);
            printf("%s.decfinal=%d\n", label, EVP_DecryptFinal_ex(dctx, dec + l1, &l2));
            printf("%s.decfinal.outl=%d\n", label, l2);
            printf("%s.roundtrip=%d\n", label,
                   l1 == (int)plen && memcmp(dec, in, plen) == 0);
            EVP_CIPHER_CTX_free(dctx);

            /* A flipped tag inside the record is the same silent refusal, and the ciphertext is
             * zeroed in place on the way out. */
            rec[plen] ^= 0x01;
            memset(dec, 0, sizeof(dec));
            ERR_clear_error();
            dctx = EVP_CIPHER_CTX_new();
            if (dctx != NULL && EVP_DecryptInit_ex2(dctx, cipher, key, nonce, NULL) == 1) {
                EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_TLS1_AAD, 13, aaddec);
                l1 = -999;
                printf("%s.bad=%d\n", label,
                       EVP_DecryptUpdate(dctx, dec, &l1, rec, (int)(plen + 16)));
                printf("%s.bad.outl=%d\n", label, l1);
                snprintf(hexlabel, sizeof(hexlabel), "%s.baddec", label);
                rt_hex(hexlabel, dec, plen);
            }
            rt_errq("chachapoly_tlsbad");
            if (dctx != NULL)
                EVP_CIPHER_CTX_free(dctx);
            rec[plen] ^= 0x01;
        }
    }

    /*
     * The fixed IV installed two ways. `tls1_meth.c:107` hands the explicit IV to
     * `EVP_CipherInit_ex`; `EVP_CTRL_AEAD_SET_IV_FIXED` is the other. Both end with the same
     * counter block, so the two records must be identical.
     */
    {
        unsigned char rec_a[128], rec_b[128], aadlen[13];
        size_t plen = 32;

        memcpy(aadlen, aad13, sizeof(aadlen));
        aadlen[11] = 0;
        aadlen[12] = (unsigned char)plen;
        memcpy(tlsfixed, nonce, sizeof(tlsfixed));
        memset(rec_a, 0, sizeof(rec_a));
        memset(rec_b, 0, sizeof(rec_b));

        ERR_clear_error();
        ctx = EVP_CIPHER_CTX_new();
        if (ctx != NULL && EVP_EncryptInit_ex2(ctx, cipher, key, tlsfixed, NULL) == 1) {
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 13, aadlen);
            printf("chachapoly.ivfix.a=%d\n",
                   EVP_EncryptUpdate(ctx, rec_a, &l1, in, (int)(plen + 16)));
        } else {
            printf("chachapoly.ivfix.a=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);

        ERR_clear_error();
        ctx = EVP_CIPHER_CTX_new();
        if (ctx != NULL
            && EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, 12, tlsfixed) == 1
            && EVP_EncryptInit_ex2(ctx, NULL, key, NULL, NULL) == 1) {
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 13, aadlen);
            printf("chachapoly.ivfix.b=%d\n",
                   EVP_EncryptUpdate(ctx, rec_b, &l2, in, (int)(plen + 16)));
            printf("chachapoly.ivfix.same=%d\n", memcmp(rec_a, rec_b, plen + 16) == 0);
        } else {
            printf("chachapoly.ivfix.b=0\n");
            printf("chachapoly.ivfix.same=0\n");
        }
        rt_errq("chachapoly_ivfix");
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
    }

    /* A `tlsivfixed` of the wrong length and a `tlsaad` of the wrong length: two refusals. */
    {
        struct {
            const char *name;
            int ctrl;
            int arg;
        } cases[2];
        size_t k;

        cases[0].name = "chachapoly.ivfixed13";
        cases[0].ctrl = EVP_CTRL_AEAD_SET_IV_FIXED;
        cases[0].arg = 13;
        cases[1].name = "chachapoly.aad12";
        cases[1].ctrl = EVP_CTRL_AEAD_TLS1_AAD;
        cases[1].arg = 12;

        for (k = 0; k < 2; k++) {
            unsigned char buf[16];
            int ans = 0;

            memset(buf, 0, sizeof(buf));
            ERR_clear_error();
            ctx = EVP_CIPHER_CTX_new();
            if (ctx != NULL && EVP_EncryptInit_ex2(ctx, cipher, key, nonce, NULL) == 1)
                ans = EVP_CIPHER_CTX_ctrl(ctx, cases[k].ctrl, cases[k].arg, buf);
            printf("%s=%d\n", cases[k].name, ans);
            rt_errq(cases[k].name);
            if (ctx != NULL)
                EVP_CIPHER_CTX_free(ctx);
        }
    }

    /* `dupctx` is a whole-context copy, poly1305 state included: a copy taken after the record is
     * announced but before it is enciphered must produce the same record. */
    {
        EVP_CIPHER_CTX *cp;
        unsigned char a2[13], whole[256], copied[256];
        size_t plen = 96;

        memcpy(a2, aad13, sizeof(a2));
        a2[11] = 0;
        a2[12] = (unsigned char)plen;
        memset(whole, 0, sizeof(whole));
        memset(copied, 0, sizeof(copied));

        ctx = EVP_CIPHER_CTX_new();
        cp = EVP_CIPHER_CTX_new();
        if (ctx != NULL && cp != NULL
            && EVP_EncryptInit_ex2(ctx, cipher, key, nonce, NULL) == 1) {
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 13, a2);
            printf("chachapoly.dup.copy=%d\n", EVP_CIPHER_CTX_copy(cp, ctx));
            printf("chachapoly.dup.whole=%d\n",
                   EVP_EncryptUpdate(ctx, whole, &l1, in, (int)(plen + 16)));
            printf("chachapoly.dup.other=%d\n",
                   EVP_EncryptUpdate(cp, copied, &l2, in, (int)(plen + 16)));
            printf("chachapoly.dup.same=%d\n",
                   memcmp(whole, copied, plen + 16) == 0);
            rt_hex("chachapoly.dup.wholehex", whole, plen + 16);
        } else {
            printf("chachapoly.dup.copy=0\n");
            printf("chachapoly.dup.same=0\n");
        }
        if (ctx != NULL)
            EVP_CIPHER_CTX_free(ctx);
        if (cp != NULL)
            EVP_CIPHER_CTX_free(cp);
    }

    EVP_CIPHER_free(cipher);
}

/*
 * The five `SM4-*` block and stream rows -- the authority's only pure block cipher with **no
 * low-level public API at all**, so the provider rows are the entire surface.
 *
 * The standard vector is the reason this arm is not just a round trip:
 * **GB/T 32907-2016 / RFC 8998** gives key = plaintext = `0123456789abcdef fedcba9876543210` and
 * ciphertext `681edf34 d206965e 86b3e94f 536e4246`, and SM4-ECB must produce exactly that block.
 * Everything else here is the row mechanics: the two block modes keep a sixteen-byte block size and
 * the three stream modes report **one byte**, which is the difference a caller reasons about.
 */
static void rt_deflt_sm4(void)
{
    static const unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const char *rows[] = { "SM4-ECB", "SM4-CBC", "SM4-CTR", "SM4-OFB", "SM4-CFB" };
    unsigned char in[64], out[128], dec[128];
    size_t r, i;

    for (i = 0; i < sizeof(in); i++)
        in[i] = (unsigned char)(i * 3 + 1);

    for (r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, rows[r], NULL);
        EVP_CIPHER_CTX *e, *d;
        int l1, l2;
        size_t olen = 0, dlen = 0;

        printf("sm4.%s.fetched=%d\n", rows[r], c != NULL);
        if (c == NULL)
            continue;

        /*
         * The standard block, through SM4-ECB with **no padding**: sixteen bytes in, sixteen out.
         * SM4-CBC would need an IV and would not show the raw block, so the vector is checked on the
         * row the standard is stated for.
         */
        if (strcmp(rows[r], "SM4-ECB") == 0) {
            EVP_CIPHER_CTX *k = EVP_CIPHER_CTX_new();
            unsigned char one[16], kout[16];
            int n = 0;

            EVP_EncryptInit_ex(k, c, NULL, key, NULL);
            EVP_CIPHER_CTX_set_padding(k, 0);
            printf("sm4.ecb.vector.update=%d\n",
                   EVP_EncryptUpdate(k, kout, &n, key, 16));
            printf("sm4.ecb.vector.len=%d\n", n);
            rt_hex("sm4.ecb.vector", kout, (size_t)n);
            printf("sm4.ecb.vector.matches=%d\n", n == 16
                   && kout[0] == 0x68 && kout[1] == 0x1e && kout[2] == 0xdf && kout[3] == 0x34
                   && kout[4] == 0xd2 && kout[5] == 0x06 && kout[6] == 0x96 && kout[7] == 0x5e
                   && kout[8] == 0x86 && kout[9] == 0xb3 && kout[10] == 0xe9 && kout[11] == 0x4f
                   && kout[12] == 0x53 && kout[13] == 0x6e && kout[14] == 0x42 && kout[15] == 0x46);
            /* And the decrypt twin, which walks the same schedule backwards. */
            memset(one, 0, sizeof(one));
            EVP_DecryptInit_ex(k, c, NULL, key, NULL);
            EVP_CIPHER_CTX_set_padding(k, 0);
            printf("sm4.ecb.vector.dec=%d\n",
                   EVP_DecryptUpdate(k, one, &n, kout, 16));
            rt_hex("sm4.ecb.vector.dec", one, (size_t)n);
            EVP_CIPHER_CTX_free(k);
        }

        /* The 64-byte round trip, with the IV only where the row takes one. */
        e = EVP_CIPHER_CTX_new();
        d = EVP_CIPHER_CTX_new();
        printf("sm4.%s.enc.init=%d\n", rows[r],
               EVP_EncryptInit_ex(e, c, NULL, key, strcmp(rows[r], "SM4-ECB") == 0 ? NULL : iv));
        EVP_CIPHER_CTX_set_padding(e, 0);
        printf("sm4.%s.enc.update=%d\n", rows[r], EVP_EncryptUpdate(e, out, &l1, in, 64));
        olen += (size_t)l1;
        printf("sm4.%s.enc.final=%d\n", rows[r], EVP_EncryptFinal_ex(e, out + olen, &l2));
        olen += (size_t)l2;
        printf("sm4.%s.enc.len=%zu\n", rows[r], olen);
        rt_hex_w("sm4", rows[r], out, olen);

        printf("sm4.%s.dec.init=%d\n", rows[r],
               EVP_DecryptInit_ex(d, c, NULL, key, strcmp(rows[r], "SM4-ECB") == 0 ? NULL : iv));
        EVP_CIPHER_CTX_set_padding(d, 0);
        printf("sm4.%s.dec.update=%d\n", rows[r], EVP_DecryptUpdate(d, dec, &l1, out, (int)olen));
        dlen += (size_t)l1;
        printf("sm4.%s.dec.final=%d\n", rows[r], EVP_DecryptFinal_ex(d, dec + dlen, &l2));
        dlen += (size_t)l2;
        printf("sm4.%s.dec.len=%zu\n", rows[r], dlen);
        printf("sm4.%s.roundtrip=%d\n", rows[r],
               dlen == 64 && memcmp(dec, in, 64) == 0);

        /* A three-way split of the same message must agree with the one-shot: the partial-block and
         * counter paths are where a stream mode and a CBC chain differ from ECB. */
        {
            EVP_CIPHER_CTX *s = EVP_CIPHER_CTX_new();
            unsigned char split[128];
            size_t slen = 0;

            EVP_EncryptInit_ex(s, c, NULL, key, strcmp(rows[r], "SM4-ECB") == 0 ? NULL : iv);
            EVP_CIPHER_CTX_set_padding(s, 0);
            EVP_EncryptUpdate(s, split, &l1, in, 13);
            slen += (size_t)l1;
            EVP_EncryptUpdate(s, split + slen, &l1, in + 13, 30);
            slen += (size_t)l1;
            EVP_EncryptUpdate(s, split + slen, &l1, in + 43, 21);
            slen += (size_t)l1;
            EVP_EncryptFinal_ex(s, split + slen, &l2);
            slen += (size_t)l2;
            printf("sm4.%s.split.len=%zu\n", rows[r], slen);
            printf("sm4.%s.split.agrees=%d\n", rows[r],
                   slen == olen && memcmp(split, out, olen) == 0);
            EVP_CIPHER_CTX_free(s);
        }

        EVP_CIPHER_CTX_free(e);
        EVP_CIPHER_CTX_free(d);
        EVP_CIPHER_free(c);
    }
}
/*
 * The twenty-one `ARIA-*` block and stream rows. Like SM4 these have **no low-level public API at
 * all** in this authority -- the provider rows are the entire surface -- so the arm is the only
 * differential evidence their wiring has.
 *
 * The arm is per-**key-size** rather than per-row alone, because that is what a wrong `kbits`
 * argument to `ossl_aria_set_*_key` looks like: the row would still fetch and still round-trip with
 * itself, and only the standard vector would disagree. RFC 5794 A gives all three widths for the
 * same plaintext, so the ECB rows are checked against the published block of their own width:
 *
 *   key = 000102...0f (16) / ...17 (24) / ...1f (32), plaintext = 00112233445566778899aabbccddeeff
 *   ciphertext = d718fbd6ab644c739da95f3be6451778 / 26449c1805dbe7aa25a468ce263a9e79
 *                                    / f92bd7c79fb72e2f2b8f80c1972d24fc
 *
 * The decrypt direction is checked for the same rows: an ARIA decrypt schedule is a *different*
 * schedule that the same forward function walks, so a row that built the encrypt schedule for both
 * directions would round-trip against itself and fail only here.
 *
 * CFB1 is included rather than skipped. In byte mode the authority's `use_bits` is clear, so the
 * generic CFB1 path multiplies by eight and the row behaves as a byte-oriented stream; that is
 * exactly the sort of claim an arm should measure rather than assume.
 */
static void rt_deflt_aria(void)
{
    static const char *rows[] = {
        "ARIA-256-ECB", "ARIA-192-ECB", "ARIA-128-ECB",
        "ARIA-256-CBC", "ARIA-192-CBC", "ARIA-128-CBC",
        "ARIA-256-OFB", "ARIA-192-OFB", "ARIA-128-OFB",
        "ARIA-256-CFB", "ARIA-192-CFB", "ARIA-128-CFB",
        "ARIA-256-CFB1", "ARIA-192-CFB1", "ARIA-128-CFB1",
        "ARIA-256-CFB8", "ARIA-192-CFB8", "ARIA-128-CFB8",
        "ARIA-256-CTR", "ARIA-192-CTR", "ARIA-128-CTR",
    };
    static const unsigned char key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char pt[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const unsigned char vec128[16] = {
        0xd7, 0x18, 0xfb, 0xd6, 0xab, 0x64, 0x4c, 0x73,
        0x9d, 0xa9, 0x5f, 0x3b, 0xe6, 0x45, 0x17, 0x78
    };
    static const unsigned char vec192[16] = {
        0x26, 0x44, 0x9c, 0x18, 0x05, 0xdb, 0xe7, 0xaa,
        0x25, 0xa4, 0x68, 0xce, 0x26, 0x3a, 0x9e, 0x79
    };
    static const unsigned char vec256[16] = {
        0xf9, 0x2b, 0xd7, 0xc7, 0x9f, 0xb7, 0x2e, 0x2f,
        0x2b, 0x8f, 0x80, 0xc1, 0x97, 0x2d, 0x24, 0xfc
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char in[64], out[128], dec[128];
    size_t r, i;

    for (i = 0; i < sizeof(in); i++)
        in[i] = (unsigned char)(i * 3 + 1);

    for (r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
        const char *row = rows[r];
        int bits = (row[5] == '2' && row[6] == '5') ? 256
                 : (row[5] == '1' && row[6] == '9') ? 192 : 128;
        /* RFC 5794's three keys are prefixes of one another, and the row's own key length decides
         * how much of `key256` the provider reads -- which is the whole point of checking all three
         * widths against their own published block. */
        const unsigned char *key = key256;
        const unsigned char *vec = bits == 256 ? vec256 : bits == 192 ? vec192 : vec128;
        int is_ecb = strcmp(row + strlen(row) - 3, "ECB") == 0;
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, row, NULL);
        EVP_CIPHER_CTX *e, *d;
        int l1, l2;
        size_t olen = 0, dlen = 0;

        printf("aria.%s.fetched=%d\n", row, c != NULL);
        if (c == NULL)
            continue;
        printf("aria.%s.keylen=%d\n", row, EVP_CIPHER_get_key_length(c));
        printf("aria.%s.ivlen=%d\n", row, EVP_CIPHER_get_iv_length(c));
        printf("aria.%s.blocksize=%d\n", row, EVP_CIPHER_get_block_size(c));

        /* The published block of this row's own key width, through ECB with no padding. */
        if (is_ecb) {
            EVP_CIPHER_CTX *k = EVP_CIPHER_CTX_new();
            unsigned char one[16], kout[16];
            int n = 0;

            EVP_EncryptInit_ex(k, c, NULL, key, NULL);
            EVP_CIPHER_CTX_set_padding(k, 0);
            printf("aria.%s.vector.update=%d\n", row,
                   EVP_EncryptUpdate(k, kout, &n, pt, 16));
            rt_hex_w("aria", row, kout, (size_t)n);
            printf("aria.%s.vector.matches=%d\n", row,
                   n == 16 && memcmp(kout, vec, 16) == 0);
            memset(one, 0, sizeof(one));
            EVP_DecryptInit_ex(k, c, NULL, key, NULL);
            EVP_CIPHER_CTX_set_padding(k, 0);
            printf("aria.%s.vector.dec=%d\n", row,
                   EVP_DecryptUpdate(k, one, &n, vec, 16));
            printf("aria.%s.vector.rt=%d\n", row, n == 16 && memcmp(one, pt, 16) == 0);
            EVP_CIPHER_CTX_free(k);
        }

        /* The 64-byte round trip, with the IV only where the row takes one. */
        e = EVP_CIPHER_CTX_new();
        d = EVP_CIPHER_CTX_new();
        printf("aria.%s.enc.init=%d\n", row,
               EVP_EncryptInit_ex(e, c, NULL, key, is_ecb ? NULL : iv));
        EVP_CIPHER_CTX_set_padding(e, 0);
        printf("aria.%s.enc.update=%d\n", row, EVP_EncryptUpdate(e, out, &l1, in, 64));
        olen += (size_t)l1;
        printf("aria.%s.enc.final=%d\n", row, EVP_EncryptFinal_ex(e, out + olen, &l2));
        olen += (size_t)l2;
        printf("aria.%s.enc.len=%zu\n", row, olen);
        rt_hex_w("aria", row, out, olen);

        printf("aria.%s.dec.init=%d\n", row,
               EVP_DecryptInit_ex(d, c, NULL, key, is_ecb ? NULL : iv));
        EVP_CIPHER_CTX_set_padding(d, 0);
        printf("aria.%s.dec.update=%d\n", row, EVP_DecryptUpdate(d, dec, &l1, out, (int)olen));
        dlen += (size_t)l1;
        printf("aria.%s.dec.final=%d\n", row, EVP_DecryptFinal_ex(d, dec + dlen, &l2));
        dlen += (size_t)l2;
        printf("aria.%s.roundtrip=%d\n", row, dlen == 64 && memcmp(dec, in, 64) == 0);

        /* A three-way split must agree with the one-shot: the partial-block and counter paths. */
        {
            EVP_CIPHER_CTX *s = EVP_CIPHER_CTX_new();
            unsigned char split[128];
            size_t slen = 0;

            EVP_EncryptInit_ex(s, c, NULL, key, is_ecb ? NULL : iv);
            EVP_CIPHER_CTX_set_padding(s, 0);
            EVP_EncryptUpdate(s, split, &l1, in, 13);
            slen += (size_t)l1;
            EVP_EncryptUpdate(s, split + slen, &l1, in + 13, 30);
            slen += (size_t)l1;
            EVP_EncryptUpdate(s, split + slen, &l1, in + 43, 21);
            slen += (size_t)l1;
            EVP_EncryptFinal_ex(s, split + slen, &l2);
            slen += (size_t)l2;
            printf("aria.%s.split.len=%zu\n", row, slen);
            printf("aria.%s.split.agrees=%d\n", row,
                   slen == olen && memcmp(split, out, olen) == 0);
            EVP_CIPHER_CTX_free(s);
        }

        EVP_CIPHER_CTX_free(e);
        EVP_CIPHER_CTX_free(d);
        EVP_CIPHER_free(c);
    }
}
/*
 * The `SM4-XTS` row. AES-XTS's shape with one structural difference that this arm exists to
 * observe: `SM4-XTS` has **two XTS standards** and defaults to the GB one.
 *
 * The load-bearing observation is therefore not the round trip -- a row that ignored
 * `xts_standard` entirely would round-trip perfectly under both -- but `sm4xts.standards_differ`:
 * the same key, IV and plaintext under the default (GB/T 17964-2021) and under `IEEE` must produce
 * **different** ciphertext, because the two tweak doublings are not interchangeable. `RT-CIPHER`
 * compares that bit against the authority, so a row that dropped the parameter, or wired both arms
 * to one function, fails on the commit that lands it.
 *
 * The rest is the row's own surface: a 32-octet key (`2 * 128` bits), a 16-octet IV, the
 * one-byte block size, a length that is not a multiple of sixteen (so ciphertext stealing is
 * exercised), the split update, `EVP_CIPHER_CTX_dup` (whose row-specific guard is the only way to
 * reach `sm4_xts_dupctx`'s two assertions), and the invalid `xts_standard` refusal.
 */
static void rt_deflt_sm4_xts(void)
{
    static const unsigned char key[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char in[64], gb[80], ieee[80], dec[80], tmp[80], p1[80], p2[80];
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    size_t i, glen = 0, ilen = 0;

    printf("sm4xts.fetched=%d\n", c != NULL);
    if (c == NULL)
        return;
    printf("sm4xts.keylen=%d\n", EVP_CIPHER_get_key_length(c));
    printf("sm4xts.ivlen=%d\n", EVP_CIPHER_get_iv_length(c));
    printf("sm4xts.blocksize=%d\n", EVP_CIPHER_get_block_size(c));
    for (i = 0; i < sizeof(in); i++)
        in[i] = (unsigned char)(i * 7 + 3);

    /*
     * The default standard, which is GB because the context is zalloc'd and `xts_standard` is 0.
     * Sixty-four octets, a whole number of blocks.
     */
    {
        EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
        int l1 = 0, l2 = 0;

        printf("sm4xts.gb.init=%d\n", EVP_EncryptInit_ex(e, c, NULL, key, iv));
        EVP_CIPHER_CTX_set_padding(e, 0);
        printf("sm4xts.gb.update=%d\n", EVP_EncryptUpdate(e, gb, &l1, in, 64));
        glen = (size_t)l1;
        printf("sm4xts.gb.final=%d\n", EVP_EncryptFinal_ex(e, gb + glen, &l2));
        glen += (size_t)l2;
        printf("sm4xts.gb.len=%zu\n", glen);
        rt_hex("sm4xts.gb", gb, glen);

        printf("sm4xts.gb.dec.init=%d\n", EVP_DecryptInit_ex(e, c, NULL, key, iv));
        EVP_CIPHER_CTX_set_padding(e, 0);
        printf("sm4xts.gb.dec.update=%d\n", EVP_DecryptUpdate(e, dec, &l1, gb, (int)glen));
        printf("sm4xts.gb.roundtrip=%d\n", l1 == 64 && memcmp(dec, in, 64) == 0);
        EVP_CIPHER_CTX_free(e);
    }

    /* And the same message under IEEE, which must differ from the GB answer. */
    {
        EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
        OSSL_PARAM p[2];
        int l1 = 0, l2 = 0;

        p[0] = OSSL_PARAM_construct_utf8_string("xts_standard", (char *)"IEEE", 0);
        p[1] = OSSL_PARAM_construct_end();
        printf("sm4xts.ieee.init=%d\n", EVP_EncryptInit_ex2(e, c, key, iv, p));
        EVP_CIPHER_CTX_set_padding(e, 0);
        printf("sm4xts.ieee.update=%d\n", EVP_EncryptUpdate(e, ieee, &l1, in, 64));
        ilen = (size_t)l1;
        printf("sm4xts.ieee.final=%d\n", EVP_EncryptFinal_ex(e, ieee + ilen, &l2));
        ilen += (size_t)l2;
        printf("sm4xts.ieee.len=%zu\n", ilen);
        rt_hex("sm4xts.ieee", ieee, ilen);
        printf("sm4xts.standards_differ=%d\n",
               glen == ilen && glen == 64 && memcmp(gb, ieee, glen) != 0);

        printf("sm4xts.ieee.dec.init=%d\n", EVP_DecryptInit_ex2(e, c, key, iv, p));
        EVP_CIPHER_CTX_set_padding(e, 0);
        printf("sm4xts.ieee.dec.update=%d\n", EVP_DecryptUpdate(e, dec, &l1, ieee, (int)ilen));
        printf("sm4xts.ieee.roundtrip=%d\n", l1 == 64 && memcmp(dec, in, 64) == 0);
        EVP_CIPHER_CTX_free(e);
    }

    /*
     * A length that is not a multiple of sixteen, in both directions. XTS's data unit is the whole
     * message and the tail is handled by ciphertext stealing, so this is where a row that routed
     * only whole blocks would differ. **The output goes to `tmp`, not to `gb`** -- the first version
     * of this arm reused `gb` here and then compared the split and the duplicate against the tail's
     * 61 bytes instead of the one-shot's 64, which read as two row defects and was this arm's own
     * mistake (D261's class, and D265's `dup` arm exactly).
     */
    {
        EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
        int l1 = 0, l2 = 0;
        size_t tlen;

        EVP_EncryptInit_ex(e, c, NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(e, 0);
        printf("sm4xts.tail.update=%d\n", EVP_EncryptUpdate(e, tmp, &l1, in, 61));
        tlen = (size_t)l1;
        printf("sm4xts.tail.final=%d\n", EVP_EncryptFinal_ex(e, tmp + tlen, &l2));
        tlen += (size_t)l2;
        printf("sm4xts.tail.len=%zu\n", tlen);
        rt_hex("sm4xts.tail", tmp, tlen);
        EVP_DecryptInit_ex(e, c, NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(e, 0);
        printf("sm4xts.tail.dec.update=%d\n", EVP_DecryptUpdate(e, dec, &l1, tmp, (int)tlen));
        printf("sm4xts.tail.roundtrip=%d\n", l1 == 61 && memcmp(dec, in, 61) == 0);
        EVP_CIPHER_CTX_free(e);
    }

    /*
     * **A split update is not the one-shot, and that is XTS rather than a defect.** `sm4_xts_cipher`
     * is the whole data unit: every `EVP_EncryptUpdate` restarts the tweak from the context's IV, so
     * two updates are two data units. The arm therefore measures the *property* rather than
     * agreement: the 16+48 split must equal what two fresh contexts produce for the same two
     * pieces, and must differ from the 64-byte one-shot.
     */
    {
        EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
        int l1 = 0, l2 = 0;
        size_t slen = 0, l1len = 0, l2len = 0;

        EVP_EncryptInit_ex(e, c, NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(e, 0);
        EVP_EncryptUpdate(e, tmp, &l1, in, 16);
        slen += (size_t)l1;
        EVP_EncryptUpdate(e, tmp + slen, &l1, in + 16, 48);
        slen += (size_t)l1;
        EVP_EncryptFinal_ex(e, tmp + slen, &l2);
        slen += (size_t)l2;
        EVP_CIPHER_CTX_free(e);
        printf("sm4xts.split.len=%zu\n", slen);

        /* The same two pieces, each in its own context and its own data unit. */
        e = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e, c, NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(e, 0);
        EVP_EncryptUpdate(e, p1, &l1, in, 16);
        l1len = (size_t)l1;
        EVP_EncryptFinal_ex(e, p1 + l1len, &l2);
        l1len += (size_t)l2;
        EVP_EncryptInit_ex(e, c, NULL, key, iv);
        EVP_EncryptUpdate(e, p2, &l1, in + 16, 48);
        l2len = (size_t)l1;
        EVP_EncryptFinal_ex(e, p2 + l2len, &l2);
        l2len += (size_t)l2;
        EVP_CIPHER_CTX_free(e);

        printf("sm4xts.split.is_two_data_units=%d\n",
               slen == l1len + l2len && slen == 64
               && memcmp(tmp, p1, l1len) == 0
               && memcmp(tmp + l1len, p2, l2len) == 0);
        printf("sm4xts.split.differs_from_oneshot=%d\n",
               slen == glen && memcmp(tmp, gb, glen) != 0);
    }

    /* `EVP_CIPHER_CTX_dup`, which is the only route to `sm4_xts_dupctx`. */
    {
        EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *d2;
        unsigned char dup[80];
        int l1 = 0;

        EVP_EncryptInit_ex(e, c, NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(e, 0);
        d2 = EVP_CIPHER_CTX_dup(e);
        printf("sm4xts.dup=%d\n", d2 != NULL);
        if (d2 != NULL) {
            printf("sm4xts.dup.update=%d\n", EVP_EncryptUpdate(d2, dup, &l1, in, 64));
            printf("sm4xts.dup.agrees=%d\n", l1 == 64 && glen == 64 && memcmp(dup, gb, 64) == 0);
            EVP_CIPHER_CTX_free(d2);
        }
        EVP_CIPHER_CTX_free(e);
    }

    /* A spelling of `xts_standard` that is neither GB nor IEEE is the row's own refusal. */
    {
        EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
        OSSL_PARAM p[2];

        p[0] = OSSL_PARAM_construct_utf8_string("xts_standard", (char *)"NO-SUCH-STANDARD", 0);
        p[1] = OSSL_PARAM_construct_end();
        printf("sm4xts.badstd.init=%d\n", EVP_EncryptInit_ex2(e, c, key, iv, p));
        rt_errq("sm4xts.badstd");
        EVP_CIPHER_CTX_free(e);
    }

    EVP_CIPHER_free(c);
}

/*
 * The `BLAKE2BMAC` and `BLAKE2SMAC` rows. One implementation instantiated twice, so the arm takes
 * the four widths as parameters rather than being written twice -- and the widths are the whole
 * difference between the rows, which is why they are printed rather than assumed.
 *
 * Three things are particular to this row. The context reports a **non-zero** size before anything
 * is set, because the parameter block's first byte *is* the digest length and `newctx` writes the
 * default into it. A key shorter than `KEYBYTES` is **zero-padded and then fed as a whole block**,
 * so an eight-byte key and a sixty-four-byte one exercise different code and the short one is what
 * says the padding is real. And `custom`/`salt` are applied from the descriptor directly, bounded
 * by their own widths, with a reason of their own each.
 *
 * Every refusal is drained: `PROV_R_INVALID_KEY_LENGTH` for a zero and an over-long key,
 * `PROV_R_NO_KEY_SET`, `PROV_R_NOT_XOF_OR_INVALID_LENGTH` at both ends of the size range,
 * `PROV_R_INVALID_CUSTOM_LENGTH` and `PROV_R_INVALID_SALT_LENGTH` -- five reasons from one unit.
 */
static void rt_deflt_blake2_mac_one(const char *name, const char *label, size_t keybytes,
                                    size_t outbytes, size_t personabytes, size_t saltbytes)
{
    static const size_t lens[] = { 0, 1, 63, 64, 127, 128, 129, 200 };
    EVP_MAC *mac = EVP_MAC_fetch(NULL, name, NULL);
    EVP_MAC_CTX *ctx;
    unsigned char key[64];
    unsigned char big[64];
    unsigned char msg[200];
    unsigned char out[64];
    unsigned char out2[64];
    OSSL_PARAM set[4];
    size_t i, outl, outl2;
    int r;

    printf("defltblake2.%s.fetched=%d\n", label, mac != NULL);
    if (mac == NULL)
        return;
    for (i = 0; i < sizeof(key); i++) {
        key[i] = (unsigned char)(0xf0u + i);
        big[i] = (unsigned char)(0x10u + i);
    }
    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)i;

    ctx = EVP_MAC_CTX_new(mac);
    printf("defltblake2.%s.ctx=%d\n", label, ctx != NULL);
    if (ctx == NULL) {
        EVP_MAC_free(mac);
        return;
    }

    rt_param_list("defltblake2", label, "gp", EVP_MAC_gettable_params(mac));
    rt_param_list("defltblake2", label, "cgp", EVP_MAC_CTX_gettable_params(ctx));
    rt_param_list("defltblake2", label, "csp", EVP_MAC_CTX_settable_params(ctx));

    /* Both published sizes are readable before anything is set, and neither is zero. */
    {
        size_t sz = 0, bs = 0;
        OSSL_PARAM g[3];

        g[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        g[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &bs);
        g[2] = OSSL_PARAM_construct_end();
        printf("defltblake2.%s.pre=%d:%zu:%zu\n", label, EVP_MAC_CTX_get_params(ctx, g), sz, bs);
    }

    /* The known answers, at every length that crosses a block boundary. */
    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        outl = 0;
        if (EVP_MAC_init(c, key, keybytes, NULL) == 1
            && EVP_MAC_update(c, msg, lens[i]) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("defltblake2.%s.kat%zu.len=%zu\n", label, lens[i], outl);
            rt_hex("defltblake2.katv", out, outl);
        } else {
            printf("defltblake2.%s.kat%zu.enclen=0\n", label, lens[i]);
        }
        EVP_MAC_CTX_free(c);
    }

    /*
     * A key shorter than the full width, which is zero-padded into the key buffer and then fed as
     * a whole block. The tag must equal the `keybytes` one only when the padding makes the two
     * keys equal, which it does not here -- the observation is that the short key is *accepted*,
     * not that it agrees with anything.
     */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        /*
         * The **same** context twice: first with a full-width key, then with an eight-byte one.
         * `blake2_setkey` pads the buffer only when the key is short, so after the second call the
         * bytes past eight are the first key's -- and `init_key` copies exactly `key_length` of
         * them, which is what makes the conditional pad unobservable. A fresh context would not
         * test that, because its buffer starts zeroed; reusing one is what a caller does and what
         * makes the sequence worth observing. See D257 for what this does and does not establish.
         */
        outl = 0;
        printf("defltblake2.%s.reuse.full=%d\n", label,
               EVP_MAC_init(c, key, keybytes, NULL));
        outl = 0;
        printf("defltblake2.%s.reuse.8=%d\n", label, EVP_MAC_init(c, key, 8, NULL));
        if (EVP_MAC_update(c, msg, 16) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("defltblake2.%s.shortkey.len=%zu\n", label, outl);
            rt_hex("defltblake2.shortkey.tag", out, outl);
        } else {
            printf("defltblake2.%s.shortkey.enclen=0\n", label);
        }
        EVP_MAC_CTX_free(c);
    }

    /* A truncated output, through the `size` parameter. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
        size_t sz = 16;

        set[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        set[1] = OSSL_PARAM_construct_end();
        printf("defltblake2.%s.size16.set=%d\n", label, EVP_MAC_CTX_set_params(c, set));
        outl = 0;
        if (EVP_MAC_init(c, key, keybytes, NULL) == 1
            && EVP_MAC_update(c, msg, 16) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("defltblake2.%s.size16.len=%zu\n", label, outl);
            rt_hex("defltblake2.size16.tag", out, outl);
        } else {
            printf("defltblake2.%s.size16.enclen=0\n", label);
        }
        EVP_MAC_CTX_free(c);
    }

    /* A whole-width output, which is not the same construction truncated. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
        size_t sz = outbytes;

        set[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        set[1] = OSSL_PARAM_construct_end();
        printf("defltblake2.%s.sizefull.set=%d\n", label, EVP_MAC_CTX_set_params(c, set));
        outl = 0;
        if (EVP_MAC_init(c, key, keybytes, NULL) == 1
            && EVP_MAC_update(c, msg, 16) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("defltblake2.%s.sizefull.len=%zu\n", label, outl);
            rt_hex("defltblake2.sizefull.tag", out, outl);
        } else {
            printf("defltblake2.%s.sizefull.enclen=0\n", label);
        }
        EVP_MAC_CTX_free(c);
    }

    /* `custom` and `salt`, at their full widths, which changes the tag. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        set[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, big, personabytes);
        set[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_SALT, big, saltbytes);
        set[2] = OSSL_PARAM_construct_end();
        printf("defltblake2.%s.cs.set=%d\n", label, EVP_MAC_CTX_set_params(c, set));
        outl = 0;
        if (EVP_MAC_init(c, key, keybytes, NULL) == 1
            && EVP_MAC_update(c, msg, 16) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("defltblake2.%s.cs.len=%zu\n", label, outl);
            rt_hex("defltblake2.cs.tag", out, outl);
        } else {
            printf("defltblake2.%s.cs.enclen=0\n", label);
        }
        EVP_MAC_CTX_free(c);
    }

    /* A key delivered through the parameter array rather than as an argument. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        set[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, keybytes);
        set[1] = OSSL_PARAM_construct_end();
        printf("defltblake2.%s.pkey.set=%d\n", label, EVP_MAC_CTX_set_params(c, set));
        outl = 0;
        if (EVP_MAC_init(c, NULL, 0, NULL) == 1
            && EVP_MAC_update(c, msg, 16) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("defltblake2.%s.pkey.len=%zu\n", label, outl);
            rt_hex("defltblake2.pkey.tag", out, outl);
        } else {
            printf("defltblake2.%s.pkey.enclen=0\n", label);
        }
        EVP_MAC_CTX_free(c);
    }

    /*
     * The duplicate. The copy is a whole-struct `memcpy` of a context that owns nothing, so a copy
     * taken mid-message continues where the original is; advancing only the copy and finalising
     * both separates a real duplicate from one that restarted. The lengths are printed only on a
     * successful final, because `evp_mac_final` copies an uninitialised local into the caller's
     * `*outl` when the row refuses (D252).
     */
    {
        EVP_MAC_CTX *a0 = EVP_MAC_CTX_new(mac);
        EVP_MAC_CTX *b0;
        int ok_copy, ok_orig;

        printf("defltblake2.%s.dup.init=%d\n", label, EVP_MAC_init(a0, key, keybytes, NULL));
        printf("defltblake2.%s.dup.update=%d\n", label, EVP_MAC_update(a0, msg, 64));
        b0 = EVP_MAC_CTX_dup(a0);
        printf("defltblake2.%s.dup.made=%d\n", label, b0 != NULL);
        if (b0 != NULL) {
            outl = 0;
            outl2 = 0;
            printf("defltblake2.%s.dup.copy.update=%d\n", label,
                   EVP_MAC_update(b0, msg + 64, 64));
            ok_copy = EVP_MAC_final(b0, out2, &outl2, sizeof(out2));
            printf("defltblake2.%s.dup.copy.final=%d\n", label, ok_copy);
            if (ok_copy)
                printf("defltblake2.%s.dup.copy.len=%zu\n", label, outl2);
            ok_orig = EVP_MAC_final(a0, out, &outl, sizeof(out));
            printf("defltblake2.%s.dup.orig.final=%d\n", label, ok_orig);
            if (ok_orig)
                printf("defltblake2.%s.dup.orig.len=%zu\n", label, outl);
            if (ok_copy)
                rt_hex("defltblake2.dup.copytag", out2, outl2);
            if (ok_orig)
                rt_hex("defltblake2.dup.origtag", out, outl);
            EVP_MAC_CTX_free(b0);
        }
        EVP_MAC_CTX_free(a0);
    }

    /* A zero-length update, which the row answers 1 for without touching the state. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        r = EVP_MAC_init(c, key, keybytes, NULL);
        printf("defltblake2.%s.zeroupd.init=%d\n", label, r);
        printf("defltblake2.%s.zeroupd.update=%d\n", label, EVP_MAC_update(c, msg, 0));
        outl = 0;
        r = EVP_MAC_final(c, out, &outl, sizeof(out));
        printf("defltblake2.%s.zeroupd.final=%d:%zu\n", label, r, outl);
        rt_hex("defltblake2.zeroupd.tag", out, outl);
        EVP_MAC_CTX_free(c);
    }

    /* The refusals, each with its queue. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
        int one = 1;

        /* A zero-length key: `blake2_setkey` refuses it as well as an over-long one. */
        ERR_clear_error();
        printf("defltblake2.%s.badkey0=%d\n", label, EVP_MAC_init(c, key, 0, NULL));
        rt_errq("blake2_badkey0");

        /* An over-long key. */
        ERR_clear_error();
        printf("defltblake2.%s.badkeybig=%d\n", label, EVP_MAC_init(c, key, keybytes + 1, NULL));
        rt_errq("blake2_badkeybig");

        /* No key by any route. */
        EVP_MAC_CTX_free(c);
        c = EVP_MAC_CTX_new(mac);
        ERR_clear_error();
        printf("defltblake2.%s.nokey=%d\n", label, EVP_MAC_init(c, NULL, 0, NULL));
        rt_errq("blake2_nokey");

        /* Both ends of the size range. */
        {
            size_t zero = 0, over = outbytes + 1;
            OSSL_PARAM a[2];

            a[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &zero);
            a[1] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            printf("defltblake2.%s.size0=%d\n", label, EVP_MAC_CTX_set_params(c, a));
            rt_errq("blake2_size0");

            a[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &over);
            ERR_clear_error();
            printf("defltblake2.%s.sizebig=%d\n", label, EVP_MAC_CTX_set_params(c, a));
            rt_errq("blake2_sizebig");
        }

        /* `custom` and `salt` past their widths, then each of them one byte inside. */
        {
            OSSL_PARAM a[2];

            a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, big, personabytes + 1);
            a[1] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            printf("defltblake2.%s.custbig=%d\n", label, EVP_MAC_CTX_set_params(c, a));
            rt_errq("blake2_custbig");

            a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_SALT, big, saltbytes + 1);
            ERR_clear_error();
            printf("defltblake2.%s.saltbig=%d\n", label, EVP_MAC_CTX_set_params(c, a));
            rt_errq("blake2_saltbig");

            a[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, big, personabytes);
            ERR_clear_error();
            printf("defltblake2.%s.custexact=%d\n", label, EVP_MAC_CTX_set_params(c, a));
            rt_errq("blake2_custexact");
        }

        /* A `key` that is not an octet string, and a repeated `size`. */
        {
            OSSL_PARAM a[3];

            a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_KEY, &one);
            a[1] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            printf("defltblake2.%s.keytype=%d\n", label, EVP_MAC_CTX_set_params(c, a));
            rt_errq("blake2_keytype");

            {
                size_t sixteen = 16;
                a[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sixteen);
                a[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sixteen);
                a[2] = OSSL_PARAM_construct_end();
            }
            ERR_clear_error();
            printf("defltblake2.%s.repeat=%d\n", label, EVP_MAC_CTX_set_params(c, a));
            rt_errq("blake2_repeat");

            /* The *get* decoder's two sites. */
            {
                size_t sz = 0;
                OSSL_PARAM g[3];

                g[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &sz);
                g[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &sz);
                g[2] = OSSL_PARAM_construct_end();
                ERR_clear_error();
                printf("defltblake2.%s.repeatbsize=%d\n", label, EVP_MAC_CTX_get_params(c, g));
                rt_errq("blake2_repeatbsize");

                /* A fresh array: reusing the `block-size` pair above would leave `g[1]` a
                 * `block-size` and make this a two-key array with no duplicate at all. */
                g[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
                g[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
                g[2] = OSSL_PARAM_construct_end();
                ERR_clear_error();
                printf("defltblake2.%s.repeatsize=%d\n", label, EVP_MAC_CTX_get_params(c, g));
                rt_errq("blake2_repeatsize");
            }
        }
        EVP_MAC_CTX_free(c);
    }

    EVP_MAC_free(mac);
}

/* Both rows, with the widths each preamble substitutes. */
static void rt_deflt_blake2_mac(void)
{
    rt_deflt_blake2_mac_one("BLAKE2BMAC", "b", 64, 64, 16, 16);
    rt_deflt_blake2_mac_one("BLAKE2SMAC", "s", 32, 32, 8, 8);
}

/*
 * The `HMAC` row, driven through `EVP_MAC`. It is the one MAC row here whose implementation is a
 * shell over another unit: `crypto/hmac/hmac.c`. So this arm has three jobs the SIPHASH one does
 * not.
 *
 * The first is that the *parameterisation* is observable. A row receives a digest **name**, not a
 * method, so `digest`/`properties` go through `ossl_prov_digest_load` in
 * `PROV_LIBCTX_OF(macctx->provctx)` -- and the size a context reports before a digest arrives is 0,
 * not the size of a default. Both are printed, before and after.
 *
 * The second is the **TLS arm**, which is the reason `ssl3_cbc_digest_record` exists in this crate
 * at all. `tls-data-size` switches the row from `HMAC_Update` to `ssl3_cbc_digest_record`, the
 * first `update` must be the 13-byte record header and is stored rather than hashed, and the second
 * must be no longer than `tls-data-size`. All four of those are observed, including the two
 * refusals, because the state machine is where a transcription of this row can disagree while
 * every ordinary HMAC still matches. The record buffer is 256 bytes on the stack and
 * `tls-data-size` is 85, so the bytes `ssl3_cbc_digest_record` reads past `datalen` are the same on
 * both sides rather than whatever the stack held -- the caller's contract is that `data` is
 * `data_plus_mac_plus_padding_size` long, and the probe honours it.
 *
 * The third is the refusals' **error queues**. A repeated `digest` is the decoder's
 * `PROV_R_REPEATED_PARAMETER` at `hmac_prov.c:427`; a `key` of the wrong type is a bare `return 0`
 * with nothing queued; and a duplicate context is where `hmac_dup`'s whole-struct copy is visible,
 * because the copy and the original are advanced differently and then compared.
 */
static void rt_deflt_hmac(void)
{
    static const size_t lens[] = { 0, 1, 16, 63, 64, 128 };
    static const unsigned char key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    unsigned char msg[256];
    unsigned char rec[256];
    unsigned char out[64];
    unsigned char out2[64];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[3];
    OSSL_PARAM set[3];
    size_t i, outl, outl2;
    int r;

    printf("deflthmac.fetched=%d\n", mac != NULL);
    if (mac == NULL)
        return;
    ctx = EVP_MAC_CTX_new(mac);
    printf("deflthmac.ctx=%d\n", ctx != NULL);
    if (ctx == NULL) {
        EVP_MAC_free(mac);
        return;
    }

    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = (unsigned char)i;
        rec[i] = (unsigned char)(0xa0u + (unsigned)i);
    }

    /* Before a digest is named, both published sizes are zero. */
    {
        size_t sz = 999, bs = 999;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        params[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &bs);
        params[2] = OSSL_PARAM_construct_end();
        printf("deflthmac.pre.get=%d:%zu:%zu\n",
               EVP_MAC_CTX_get_params(ctx, params), sz, bs);
    }

    /* The digest arrives as a name, in the init params. */
    {
        const char *digest = "SHA256";
        OSSL_PARAM ip[2];

        ip[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)digest, 0);
        ip[1] = OSSL_PARAM_construct_end();
        printf("deflthmac.sha256.init=%d\n", EVP_MAC_init(ctx, key, sizeof(key), ip));
    }
    {
        size_t sz = 999, bs = 999;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        params[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &bs);
        params[2] = OSSL_PARAM_construct_end();
        printf("deflthmac.post.get=%d:%zu:%zu\n",
               EVP_MAC_CTX_get_params(ctx, params), sz, bs);
    }

    /*
     * The two published parameter lists, in order. A caller introspects these, so the names and
     * their sequence are part of the row's contract rather than an implementation detail -- and the
     * *set* list for a MAC row is the one a caller builds its `set_ctx_params` array from.
     */
    {
        const OSSL_PARAM *p;
        const char *kind[2];
        int k;

        kind[0] = "get";
        kind[1] = "set";
        for (k = 0; k < 2; k++) {
            size_t n = 0;

            p = k == 0 ? EVP_MAC_CTX_gettable_params(ctx)
                       : EVP_MAC_CTX_settable_params(ctx);
            printf("deflthmac.list.%s.present=%d\n", kind[k], p != NULL);
            if (p == NULL)
                continue;
            for (; p->key != NULL; p++) {
                printf("deflthmac.list.%s.%zu=%s:%u:%zu\n", kind[k], n, p->key,
                       p->data_type, p->data_size);
                n++;
            }
            printf("deflthmac.list.%s.count=%zu\n", kind[k], n);
        }
    }
    /* `EVP_MAC_gettable_params` on the fetched MAC itself: HMAC publishes no provider-level list. */
    {
        const OSSL_PARAM *p = EVP_MAC_gettable_params(mac);

        printf("deflthmac.list.provider.present=%d\n", p != NULL);
        if (p != NULL)
            printf("deflthmac.list.provider.first=%s\n", p->key != NULL ? p->key : "");
    }

    /* The known answers, at every length that crosses a block boundary. */
    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
        OSSL_PARAM ip[2];
        const char *digest = "SHA256";

        ip[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)digest, 0);
        ip[1] = OSSL_PARAM_construct_end();
        outl = 0;
        if (EVP_MAC_init(c, key, sizeof(key), ip) == 1
            && EVP_MAC_update(c, msg, lens[i]) == 1
            && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
            printf("deflthmac.kat%zu.len=%zu\n", lens[i], outl);
            rt_hex("deflthmac.katv", out, outl);
        } else {
            printf("deflthmac.kat%zu.enclen=0\n", lens[i]);
        }
        EVP_MAC_CTX_free(c);
    }

    /* SHA-1 and SHA-512 as well, because the digest dispatch is what the TLS arm keys off. */
    {
        static const char *names[] = { "SHA1", "SHA512", "SHA2-224" };

        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
            OSSL_PARAM ip[2];

            ip[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                     (char *)names[i], 0);
            ip[1] = OSSL_PARAM_construct_end();
            outl = 0;
            if (EVP_MAC_init(c, key, sizeof(key), ip) == 1
                && EVP_MAC_update(c, msg, 16) == 1
                && EVP_MAC_final(c, out, &outl, sizeof(out)) == 1) {
                printf("deflthmac.%s.len=%zu\n", names[i], outl);
                rt_hex("deflthmac.digv", out, outl);
            } else {
                printf("deflthmac.%s.enclen=0\n", names[i]);
            }
            EVP_MAC_CTX_free(c);
        }
    }

    /*
     * A key set through `set_ctx_params` rather than through `init`, then the same message. The
     * tag must equal the init-keyed one, because both paths end in `HMAC_Init_ex` over the same
     * key -- and a row that ignored the params key would produce the previous key's tag.
     */
    EVP_MAC_CTX_free(ctx);
    ctx = EVP_MAC_CTX_new(mac);
    {
        const char *digest = "SHA256";

        set[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                  (char *)digest, 0);
        set[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)key,
                                                   sizeof(key));
        set[2] = OSSL_PARAM_construct_end();
        printf("deflthmac.set.digestkey=%d\n", EVP_MAC_CTX_set_params(ctx, set));
    }
    outl = 0;
    if (EVP_MAC_init(ctx, NULL, 0, NULL) == 1
        && EVP_MAC_update(ctx, msg, 16) == 1
        && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1) {
        printf("deflthmac.paramkey.len=%zu\n", outl);
        rt_hex("deflthmac.paramkey.tag", out, outl);
    } else {
        printf("deflthmac.paramkey.enclen=0\n");
    }

    /* A re-init with NULLs restarts from the stored key rather than failing. */
    outl = 0;
    if (EVP_MAC_init(ctx, NULL, 0, NULL) == 1
        && EVP_MAC_update(ctx, msg, 16) == 1
        && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1) {
        rt_hex("deflthmac.reinit.tag", out, outl);
    } else {
        printf("deflthmac.reinit.enclen=0\n");
    }
    EVP_MAC_CTX_free(ctx);

    /*
     * The duplicate. The copy takes the whole struct, so a copy made mid-message continues from
     * where the original is; advancing only the copy and then finalising both is the observation
     * that separates a real duplicate from one that restarted.
     *
     * **The lengths are printed only when the final succeeded**, and that is deliberate rather than
     * defensive. `evp_mac_final` writes `*outl = l` from an uninitialised local when the row's
     * `final` returns 0 without writing its own `*outl`, so a failed final leaves the caller's
     * length indeterminate on *both* sides. Reading it would be a transcription of undefined
     * behaviour and the two transcripts could not be compared at all.
     */
    {
        EVP_MAC_CTX *a0 = EVP_MAC_CTX_new(mac);
        EVP_MAC_CTX *b0;
        const char *digest = "SHA256";
        OSSL_PARAM ip[2];
        int ok_copy, ok_orig;

        ip[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)digest, 0);
        ip[1] = OSSL_PARAM_construct_end();
        printf("deflthmac.dup.init=%d\n", EVP_MAC_init(a0, key, sizeof(key), ip));
        printf("deflthmac.dup.update=%d\n", EVP_MAC_update(a0, msg, 32));
        b0 = EVP_MAC_CTX_dup(a0);
        printf("deflthmac.dup.made=%d\n", b0 != NULL);
        if (b0 != NULL) {
            outl = 0;
            outl2 = 0;
            printf("deflthmac.dup.copy.update=%d\n", EVP_MAC_update(b0, msg + 32, 32));
            ok_copy = EVP_MAC_final(b0, out2, &outl2, sizeof(out2));
            printf("deflthmac.dup.copy.final=%d\n", ok_copy);
            if (ok_copy)
                printf("deflthmac.dup.copy.len=%zu\n", outl2);
            ok_orig = EVP_MAC_final(a0, out, &outl, sizeof(out));
            printf("deflthmac.dup.orig.final=%d\n", ok_orig);
            if (ok_orig)
                printf("deflthmac.dup.orig.len=%zu\n", outl);
            if (ok_copy)
                rt_hex("deflthmac.dup.copytag", out2, outl2);
            if (ok_orig)
                rt_hex("deflthmac.dup.origtag", out, outl);
            EVP_MAC_CTX_free(b0);
        }
        EVP_MAC_CTX_free(a0);
    }

    /*
     * The TLS arm. `tls-data-size` is the whole decrypted record: 37 bytes of data, a 32-byte MAC
     * and 16 bytes of padding is 85, and `rec` is 256 bytes, so the neighbourhood
     * `ssl3_cbc_digest_record` scans is initialised on both sides.
     */
    {
        const char *digest = "SHA256";
        size_t tlssize = 37 + 32 + 16;
        OSSL_PARAM ip[3];
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        ip[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)digest, 0);
        ip[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, &tlssize);
        ip[2] = OSSL_PARAM_construct_end();
        printf("deflthmac.tls.init=%d\n", EVP_MAC_init(c, key, sizeof(key), ip));
        outl = 0;
        printf("deflthmac.tls.header=%d\n", EVP_MAC_update(c, rec, 13));
        printf("deflthmac.tls.body=%d\n", EVP_MAC_update(c, rec + 13, 37));
        printf("deflthmac.tls.final=%d\n", EVP_MAC_final(c, out, &outl, sizeof(out)));
        printf("deflthmac.tls.len=%zu\n", outl);
        rt_hex("deflthmac.tls.tag", out, outl);
        EVP_MAC_CTX_free(c);
    }

    /* The TLS refusals, each with its queue. */
    {
        const char *digest = "SHA256";
        size_t tlssize = 85;
        OSSL_PARAM ip[3];
        EVP_MAC_CTX *c;

        /* A first update that is not the 13-byte header. */
        c = EVP_MAC_CTX_new(mac);
        ip[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)digest, 0);
        ip[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, &tlssize);
        ip[2] = OSSL_PARAM_construct_end();
        EVP_MAC_init(c, key, sizeof(key), ip);
        ERR_clear_error();
        printf("deflthmac.tls.badheader=%d\n", EVP_MAC_update(c, rec, 12));
        rt_errq("hmac_tls_badheader");
        EVP_MAC_CTX_free(c);

        /* A body longer than the record it claims to arrive in. */
        c = EVP_MAC_CTX_new(mac);
        EVP_MAC_init(c, key, sizeof(key), ip);
        EVP_MAC_update(c, rec, 13);
        ERR_clear_error();
        printf("deflthmac.tls.longbody=%d\n", EVP_MAC_update(c, rec + 13, 86));
        rt_errq("hmac_tls_longbody");
        EVP_MAC_CTX_free(c);

        /* A TLS context that never saw a body: `tls_mac_out_size` is still zero. */
        c = EVP_MAC_CTX_new(mac);
        EVP_MAC_init(c, key, sizeof(key), ip);
        EVP_MAC_update(c, rec, 13);
        ERR_clear_error();
        outl = 0;
        printf("deflthmac.tls.earlyfinal=%d\n", EVP_MAC_final(c, out, &outl, sizeof(out)));
        rt_errq("hmac_tls_earlyfinal");
        EVP_MAC_CTX_free(c);
    }

    /* The parameter refusals. Each arm builds its own array: reusing one would leave a previous
     * arm's `digest` in place and turn a key-type refusal into a repeated-parameter one. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
        int one = 1;
        OSSL_PARAM a[3];

        /* A repeated `digest`: the decoder's own raise, at its own coordinate. */
        a[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0);
        a[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA1", 0);
        a[2] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        printf("deflthmac.set.repeat=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("hmac_set_repeat");

        /* A `key` that is not an octet string: a bare zero, nothing queued. */
        a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_KEY, &one);
        a[1] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        printf("deflthmac.set.keytype=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("hmac_set_keytype");

        /* A digest nobody publishes: the fetch fails and the row reports it. The failed fetch's
         * own queue entries are the ones `ossl_prov_digest_load` pops on the legacy fallback and
         * clears when there is none, so what remains is what the row left. */
        a[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                (char *)"no-such-digest", 0);
        a[1] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        printf("deflthmac.set.baddigest=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("hmac_set_baddigest");

        /* A `tls-data-size` that is not a number: the size_t getter refuses. */
        a[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_TLS_DATA_SIZE, &one);
        a[1] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        printf("deflthmac.set.tlsnotnum=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("hmac_set_tlsnotnum");

        /* A repeated `block-size`, then a repeated `size`: the *get* decoder's two own raises. */
        {
            OSSL_PARAM g[3];
            size_t bs = 0, sz = 0;

            g[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &bs);
            g[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &bs);
            g[2] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            printf("deflthmac.get.repeatbsize=%d\n", EVP_MAC_CTX_get_params(c, g));
            rt_errq("hmac_get_repeatbsize");

            g[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
            g[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
            g[2] = OSSL_PARAM_construct_end();
            ERR_clear_error();
            printf("deflthmac.get.repeatsize=%d\n", EVP_MAC_CTX_get_params(c, g));
            rt_errq("hmac_get_repeatsize");
        }

        /* A property query that nothing satisfies, then one that this row does. */
        a[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0);
        a[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES,
                                                (char *)"fips=yes", 0);
        a[2] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        printf("deflthmac.set.propfips=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("hmac_set_propfips");

        a[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0);
        a[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES,
                                                (char *)"provider=default", 0);
        a[2] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        printf("deflthmac.set.propeq=%d\n", EVP_MAC_CTX_set_params(c, a));
        rt_errq("hmac_set_propeq");

        EVP_MAC_CTX_free(c);
    }

    /* A final whose buffer is smaller than the tag: refused by `evp_mac_final`, not by the row. */
    {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
        const char *digest = "SHA256";
        OSSL_PARAM ip[2];

        ip[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)digest, 0);
        ip[1] = OSSL_PARAM_construct_end();
        EVP_MAC_init(c, key, sizeof(key), ip);
        EVP_MAC_update(c, msg, 16);
        ERR_clear_error();
        outl = 0;
        printf("deflthmac.final.short=%d\n", EVP_MAC_final(c, out, &outl, 7));
        rt_errq("hmac_final_short");
        EVP_MAC_CTX_free(c);
    }

    EVP_MAC_free(mac);
}

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
typedef int (*rt_getctxparams_fn)(void *, OSSL_PARAM *);
typedef int (*rt_setctxparams_fn)(void *, const OSSL_PARAM *);
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

    /* ---- AES-128-CCM: the provider error-queue paths EVP cannot reach ---- */
    {
        rt_getctxparams_fn getctxparams;
        rt_setctxparams_fn setctxparams;
        OSSL_PARAM params[4];
        size_t sz = 12;
        unsigned char ctag[16];

        d = rt_disp(algs, "AES-128-CCM");
        printf("disp.ccm=%d\n", d != NULL);
        newctx = (rt_newctx_fn)rt_fn(d, OSSL_FUNC_CIPHER_NEWCTX);
        einit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_ENCRYPT_INIT);
        update = (rt_update_fn)rt_fn(d, OSSL_FUNC_CIPHER_UPDATE);
        freectx = (rt_free_fn)rt_fn(d, OSSL_FUNC_CIPHER_FREECTX);
        getctxparams = (rt_getctxparams_fn)rt_fn(d, OSSL_FUNC_CIPHER_GET_CTX_PARAMS);
        setctxparams = (rt_setctxparams_fn)rt_fn(d, OSSL_FUNC_CIPHER_SET_CTX_PARAMS);
        memset(ctag, 0x5a, sizeof(ctag));

        /* An IV length outside the row's 7..13 window: the default `l = 8` makes `15 - 8` the
         * only length bare `EVP_EncryptInit_ex2` can supply, and 16 is not it. */
        ctx = newctx(pctx);
        ERR_clear_error();
        r = einit(ctx, key, 16, iv, 16, NULL);
        printf("disp.ccmivlen.ret=%d\n", r);
        rt_errq("ccmivlen");
        freectx(ctx);

        /* A key length the row does not have, after the IV passed its own check. */
        ctx = newctx(pctx);
        ERR_clear_error();
        r = einit(ctx, key, 17, iv, 7, NULL);
        printf("disp.ccmkeylen.ret=%d\n", r);
        rt_errq("ccmkeylen");
        freectx(ctx);

        /* An output buffer that is too small, checked before any state is consulted. */
        ctx = newctx(pctx);
        ERR_clear_error();
        r = einit(ctx, key, 16, iv, 7, NULL);
        outl = 0;
        r = update(ctx, out, &outl, 8, in, 32);
        printf("disp.ccmsmall.update=%d\n", r);
        rt_errq("ccmsmall");
        freectx(ctx);

        /* No key: the stream update's own CIPHER_OPERATION_FAILED, which is a *raised* refusal
         * even though `ccm_cipher_internal` itself returns 0 without raising. */
        ctx = newctx(pctx);
        ERR_clear_error();
        r = einit(ctx, NULL, 0, NULL, 0, NULL);
        outl = 0;
        r = update(ctx, out, &outl, sizeof(out), in, 32);
        printf("disp.ccmnokey.update=%d\n", r);
        rt_errq("ccmnokey");
        freectx(ctx);

        /* The tag-length window from `set_ctx_params`: 3 is odd, 18 is over the top. */
        ctx = newctx(pctx);
        ERR_clear_error();
        einit(ctx, NULL, 0, NULL, 0, NULL);
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 3);
        params[1] = OSSL_PARAM_construct_end();
        printf("disp.ccmtag3.ret=%d\n", setctxparams(ctx, params));
        rt_errq("ccmtag3");
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 18);
        printf("disp.ccmtag18.ret=%d\n", setctxparams(ctx, params));
        rt_errq("ccmtag18");

        /* A tag *value* on the encryption side is refused: the tag is an output there. */
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, ctag, 16);
        printf("disp.ccmtagval.ret=%d\n", setctxparams(ctx, params));
        rt_errq("ccmtagval");

        /* The TLS AAD arm's two length checks: a 12-octet AAD, and a fixed IV that is not four. */
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, ctag, 12);
        printf("disp.ccmaadlen.ret=%d\n", setctxparams(ctx, params));
        rt_errq("ccmaadlen");
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, ctag, 5);
        printf("disp.ccmfixedlen.ret=%d\n", setctxparams(ctx, params));
        rt_errq("ccmfixedlen");

        /* The generated decoder's repeated-parameter refusal, at the decoder's own site. */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &sz);
        params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &sz);
        params[2] = OSSL_PARAM_construct_end();
        printf("disp.ccmdup.ret=%d\n", setctxparams(ctx, params));
        rt_errq("ccmdup");

        /* `get_ctx_params`' tag arm on a context whose encryption side has no tag yet. */
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, ctag, 16);
        params[1] = OSSL_PARAM_construct_end();
        printf("disp.ccmnotset.ret=%d\n", getctxparams(ctx, params));
        rt_errq("ccmnotset");
        freectx(ctx);
    }

    /* ---- AES-128-SIV: the four reachable provider refusals ---- */
    {
        rt_setctxparams_fn setctxparams;
        OSSL_PARAM params[3];
        unsigned int speed = 1;
        size_t klen = 16;

        d = rt_disp(algs, "AES-128-SIV");
        printf("disp.siv=%d\n", d != NULL);
        newctx = (rt_newctx_fn)rt_fn(d, OSSL_FUNC_CIPHER_NEWCTX);
        einit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_ENCRYPT_INIT);
        dinit = (rt_init_fn)rt_fn(d, OSSL_FUNC_CIPHER_DECRYPT_INIT);
        update = (rt_update_fn)rt_fn(d, OSSL_FUNC_CIPHER_UPDATE);
        freectx = (rt_free_fn)rt_fn(d, OSSL_FUNC_CIPHER_FREECTX);
        setctxparams = (rt_setctxparams_fn)rt_fn(d, OSSL_FUNC_CIPHER_SET_CTX_PARAMS);

        /* The key is twice the algorithm's: 31 octets is neither half of a pair. */
        ctx = newctx(pctx);
        ERR_clear_error();
        r = einit(ctx, key, 31, NULL, 0, NULL);
        printf("disp.sivkeylen.ret=%d\n", r);
        rt_errq("sivkeylen");
        freectx(ctx);

        /* A non-NULL output with too little room. The `out != NULL` guard is why the AAD and
         * final calls, which pass NULL, are not refused here. */
        ctx = newctx(pctx);
        ERR_clear_error();
        r = einit(ctx, key, 32, NULL, 0, NULL);
        outl = 0;
        r = update(ctx, out, &outl, 8, in, 32);
        printf("disp.sivsmall.update=%d\n", r);
        rt_errq("sivsmall");
        freectx(ctx);

        /* A tag parameter of the wrong type on a *decryption* context: the encryption side
         * returns success without looking. */
        ctx = newctx(pctx);
        ERR_clear_error();
        r = dinit(ctx, key, 32, NULL, 0, NULL);
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_AEAD_TAG, &speed);
        params[1] = OSSL_PARAM_construct_end();
        printf("disp.sivtagtype.ret=%d\n", setctxparams(ctx, params));
        rt_errq("sivtagtype");

        /* A `speed` of the wrong type. */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_SPEED, &klen);
        printf("disp.sivspeedtype.ret=%d\n", setctxparams(ctx, params));
        rt_errq("sivspeedtype");

        /* A `keylen` that does not parse, and one that parses but differs -- the second is a
         * bare `return 0` with *no* raise, which the drained queue shows. */
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_KEYLEN, &speed);
        printf("disp.sivkeylentype.ret=%d\n", setctxparams(ctx, params));
        rt_errq("sivkeylentype");
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &klen);
        printf("disp.sivkeylenmismatch.ret=%d\n", setctxparams(ctx, params));
        rt_errq("sivkeylenmismatch");
        freectx(ctx);

        /* A tag on an *encryption* context is ignored with success rather than refused. */
        ctx = newctx(pctx);
        ERR_clear_error();
        r = einit(ctx, key, 32, NULL, 0, NULL);
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, out, 16);
        params[1] = OSSL_PARAM_construct_end();
        printf("disp.sivtagenc.ret=%d\n", setctxparams(ctx, params));
        rt_errq("sivtagenc");
        freectx(ctx);
    }

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
    rt_deflt_ccm();
    rt_deflt_siv();
    rt_cbchmac_records();
    rt_gcm_siv_records();
    rt_deflt_row_census();
    rt_deflt_properties();
    rt_deflt_siphash();
    rt_deflt_hmac();
    rt_deflt_blake2_mac();
    rt_deflt_poly1305();
    rt_deflt_kmac();
    rt_deflt_chacha20();
    rt_deflt_chacha20_poly1305();
    rt_deflt_sm4();
    rt_deflt_aria();
    rt_deflt_sm4_xts();
    rt_deflt_errors();
    rt_disp_failures();
    return 0;
}
