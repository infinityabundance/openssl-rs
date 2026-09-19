/*
 * openssl-rs — the cipher correctness probe (CT-CIPHER).
 *
 * This program is compiled **once**, against the candidate distribution shell alone, and its
 * answers are compared with committed expected bytes. There is no authority transcript: the
 * differential question is RT-CIPHER's. `forensics/tools/correctness_vectors.py` owns the
 * comparison and the vector provenance.
 *
 * The protocol is the digest correctness probe's, with a cipher-shaped record: each line of
 * the calls file is `index<TAB>cipher<TAB>operation<TAB>key<TAB>iv<TAB>input`, every field
 * but the first three hex (empty where the construction has none), and the probe prints
 * `index<TAB>ok<TAB><hex>` or `index<TAB>err<TAB><reason>`. A single mismatched vector fails
 * the court loudly.
 *
 * A returned pointer is never printed; only the bytes it points at are.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/camellia.h>
#include <openssl/cast.h>
#include <openssl/core_names.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/idea.h>
#include <openssl/modes.h>
#include <openssl/rc2.h>
#include <openssl/rc4.h>
#include <openssl/seed.h>

#define CT_LINE 8192
#define CT_MAX 4096

static int ct_unhex(const char *hex, unsigned char *out, size_t cap, size_t *len)
{
    size_t n = strlen(hex), i;

    if (n % 2 != 0 || n / 2 > cap)
        return -1;
    for (i = 0; i < n / 2; i++) {
        unsigned int b;

        if (sscanf(hex + 2 * i, "%2x", &b) != 1)
            return -1;
        out[i] = (unsigned char)b;
    }
    *len = n / 2;
    return 0;
}

static void ct_hex(char *dst, const unsigned char *p, size_t n)
{
    static const char *d = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        dst[2 * i] = d[p[i] >> 4];
        dst[2 * i + 1] = d[p[i] & 0xf];
    }
    dst[2 * n] = '\0';
}

/* Run the AES and RC4 arms; return 0 with the output in `out`/`outlen`, -1 to refuse. */
static int ct_aes_rc4(const char *cipher, int enc_op,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen,
                      const unsigned char *in, size_t inlen,
                      unsigned char *out, size_t *outlen)
{
    AES_KEY enc, dck;
    unsigned char ivec[32];
    int bits;

    if (strcmp(cipher, "RC4") == 0) {
        RC4_KEY rk;

        if (keylen == 0 || ivlen != 0)
            return -1;
        memset(&rk, 0, sizeof(rk));
        RC4_set_key(&rk, (int)keylen, key);
        RC4(&rk, inlen, in, out);
        *outlen = inlen;
        return 0;
    }

    if (strncmp(cipher, "AES-", 4) != 0)
        return -1;
    bits = atoi(cipher + 4);
    if (bits != 128 && bits != 192 && bits != 256)
        return -1;
    if (keylen != (size_t)bits / 8)
        return -1;
    if (ivlen > sizeof(ivec))
        return -1;
    memcpy(ivec, iv, ivlen);
    if (AES_set_encrypt_key(key, bits, &enc) != 0)
        return -1;

    if (strstr(cipher, "-ECB") != NULL) {
        size_t blocks = inlen / 16, i;

        if (inlen % 16 != 0 || !enc_op)
            return -1;
        for (i = 0; i < blocks; i++)
            AES_ecb_encrypt(in + 16 * i, out + 16 * i, &enc, AES_ENCRYPT);
        *outlen = blocks * 16;
        return 0;
    }
    if (strstr(cipher, "-CBC") != NULL) {
        if (inlen % 16 != 0 || ivlen != 16)
            return -1;
        if (enc_op) {
            AES_cbc_encrypt(in, out, inlen, &enc, ivec, AES_ENCRYPT);
        } else {
            if (AES_set_decrypt_key(key, bits, &dck) != 0)
                return -1;
            AES_cbc_encrypt(in, out, inlen, &dck, ivec, AES_DECRYPT);
        }
        *outlen = inlen;
        return 0;
    }
    if (strstr(cipher, "-CFB") != NULL) {
        int num = 0;

        if (ivlen != 16)
            return -1;
        AES_cfb128_encrypt(in, out, inlen, &enc, ivec, &num,
                           enc_op ? AES_ENCRYPT : AES_DECRYPT);
        *outlen = inlen;
        return 0;
    }
    if (strstr(cipher, "-OFB") != NULL) {
        int num = 0;

        if (ivlen != 16)
            return -1;
        AES_ofb128_encrypt(in, out, inlen, &enc, ivec, &num);
        *outlen = inlen;
        return 0;
    }
    return -1;
}

/* The mode suffix, one of "ECB", "CBC", "CFB", "OFB", "CTR", or NULL. */
static const char *ct_mode(const char *cipher)
{
    static const char *modes[] = { "ECB", "CBC", "CFB", "OFB", "CTR" };
    char needle[8];
    size_t i;

    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        snprintf(needle, sizeof(needle), "-%s", modes[i]);
        if (strstr(cipher, needle) != NULL)
            return modes[i];
    }
    return NULL;
}

/*
 * The 8-byte-block and 16-byte-block legacy ciphers. Each returns 0 with the output in
 * `out`/`outlen` or -1 to refuse, exactly as the AES arm does.
 */
static int ct_legacy(const char *cipher, int enc_op,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen,
                     const unsigned char *in, size_t inlen,
                     unsigned char *out, size_t *outlen)
{
    const char *mode = ct_mode(cipher);
    unsigned char ivec[32];
    size_t block;

    if (mode == NULL)
        return -1;

    if (strncmp(cipher, "DES-EDE3-", 9) == 0) {
        DES_key_schedule k1, k2, k3;
        DES_cblock ck;
        int num = 0;

        if (keylen != 24 || ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        memcpy(ck, key, 8);
        DES_set_key_unchecked(&ck, &k1);
        memcpy(ck, key + 8, 8);
        DES_set_key_unchecked(&ck, &k2);
        memcpy(ck, key + 16, 8);
        DES_set_key_unchecked(&ck, &k3);
        if (strcmp(mode, "ECB") == 0) {
            size_t i;

            if (inlen % 8 != 0)
                return -1;
            for (i = 0; i < inlen; i += 8)
                DES_ecb3_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i),
                                 &k1, &k2, &k3, enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 8 != 0 || ivlen != 8)
                return -1;
            DES_ede3_cbc_encrypt(in, out, (long)inlen, &k1, &k2, &k3, ivec,
                                 enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            DES_ede3_cfb64_encrypt(in, out, (long)inlen, &k1, &k2, &k3, ivec, &num,
                                   enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "OFB") == 0) {
            DES_ede3_ofb64_encrypt(in, out, (long)inlen, &k1, &k2, &k3, ivec, &num);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    if (strncmp(cipher, "DES-EDE-", 8) == 0) {
        /* Two-key EDE, which the low-level spells as EDE3 with ks1 for ks3. */
        DES_key_schedule k1, k2;
        DES_cblock ck;
        int num = 0;

        if ((keylen != 16 && keylen != 24) || ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        memcpy(ck, key, 8);
        DES_set_key_unchecked(&ck, &k1);
        memcpy(ck, key + 8, 8);
        DES_set_key_unchecked(&ck, &k2);
        if (strcmp(mode, "ECB") == 0) {
            size_t i;

            if (inlen % 8 != 0)
                return -1;
            for (i = 0; i < inlen; i += 8)
                DES_ecb3_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i),
                                 &k1, &k2, &k1, enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 8 != 0 || ivlen != 8)
                return -1;
            DES_ede3_cbc_encrypt(in, out, (long)inlen, &k1, &k2, &k1, ivec,
                                 enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            DES_ede3_cfb64_encrypt(in, out, (long)inlen, &k1, &k2, &k1, ivec, &num,
                                   enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    if (strncmp(cipher, "DES-", 4) == 0) {
        DES_key_schedule k1;
        DES_cblock ck;
        int num = 0;

        if (keylen != 8 || ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        memcpy(ck, key, 8);
        DES_set_key_unchecked(&ck, &k1);
        if (strcmp(mode, "ECB") == 0) {
            size_t i;

            if (inlen % 8 != 0)
                return -1;
            for (i = 0; i < inlen; i += 8)
                DES_ecb_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i), &k1,
                                enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 8 != 0 || ivlen != 8)
                return -1;
            DES_ncbc_encrypt(in, out, (long)inlen, &k1, ivec,
                             enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            DES_cfb64_encrypt(in, out, (long)inlen, &k1, ivec, &num,
                              enc_op ? DES_ENCRYPT : DES_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "OFB") == 0) {
            DES_ofb64_encrypt(in, out, (long)inlen, &k1, ivec, &num);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    if (strncmp(cipher, "RC2-", 4) == 0) {
        RC2_KEY rk;
        int num = 0;
        int bits = 128;

        if (strstr(cipher, "RC2-40-") != NULL)
            bits = 40;
        else if (strstr(cipher, "RC2-64-") != NULL)
            bits = 64;
        if (ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        RC2_set_key(&rk, (int)keylen, key, bits);
        if (strcmp(mode, "ECB") == 0) {
            size_t i;

            if (inlen % 8 != 0)
                return -1;
            for (i = 0; i < inlen; i += 8)
                RC2_ecb_encrypt(in + i, out + i, &rk, enc_op ? RC2_ENCRYPT : RC2_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 8 != 0 || ivlen != 8)
                return -1;
            RC2_cbc_encrypt(in, out, (long)inlen, &rk, ivec,
                            enc_op ? RC2_ENCRYPT : RC2_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            RC2_cfb64_encrypt(in, out, (long)inlen, &rk, ivec, &num,
                              enc_op ? RC2_ENCRYPT : RC2_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "OFB") == 0) {
            RC2_ofb64_encrypt(in, out, (long)inlen, &rk, ivec, &num);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    if (strncmp(cipher, "BF-", 3) == 0) {
        BF_KEY bk;
        int num = 0;

        if (ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        BF_set_key(&bk, (int)keylen, key);
        if (strcmp(mode, "ECB") == 0) {
            size_t i;

            if (inlen % 8 != 0)
                return -1;
            for (i = 0; i < inlen; i += 8)
                BF_ecb_encrypt(in + i, out + i, &bk, enc_op ? BF_ENCRYPT : BF_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 8 != 0 || ivlen != 8)
                return -1;
            BF_cbc_encrypt(in, out, (long)inlen, &bk, ivec,
                           enc_op ? BF_ENCRYPT : BF_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            BF_cfb64_encrypt(in, out, (long)inlen, &bk, ivec, &num,
                             enc_op ? BF_ENCRYPT : BF_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "OFB") == 0) {
            BF_ofb64_encrypt(in, out, (long)inlen, &bk, ivec, &num);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    if (strncmp(cipher, "CAST5-", 6) == 0) {
        CAST_KEY ck;
        int num = 0;

        if (ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        CAST_set_key(&ck, (int)keylen, key);
        if (strcmp(mode, "ECB") == 0) {
            size_t i;

            if (inlen % 8 != 0)
                return -1;
            for (i = 0; i < inlen; i += 8)
                CAST_ecb_encrypt(in + i, out + i, &ck, enc_op ? CAST_ENCRYPT : CAST_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 8 != 0 || ivlen != 8)
                return -1;
            CAST_cbc_encrypt(in, out, (long)inlen, &ck, ivec,
                             enc_op ? CAST_ENCRYPT : CAST_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            CAST_cfb64_encrypt(in, out, (long)inlen, &ck, ivec, &num,
                               enc_op ? CAST_ENCRYPT : CAST_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "OFB") == 0) {
            CAST_ofb64_encrypt(in, out, (long)inlen, &ck, ivec, &num);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    if (strncmp(cipher, "IDEA-", 5) == 0) {
        IDEA_KEY_SCHEDULE ek, dk;
        int num = 0;

        if (keylen != 16 || ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        IDEA_set_encrypt_key(key, &ek);
        IDEA_set_decrypt_key(&ek, &dk);
        if (strcmp(mode, "ECB") == 0) {
            IDEA_KEY_SCHEDULE *ks = enc_op ? &ek : &dk;
            size_t i;

            if (inlen % 8 != 0)
                return -1;
            for (i = 0; i < inlen; i += 8)
                IDEA_ecb_encrypt(in + i, out + i, ks);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 8 != 0 || ivlen != 8)
                return -1;
            IDEA_cbc_encrypt(in, out, (long)inlen, enc_op ? &ek : &dk, ivec,
                             enc_op ? IDEA_ENCRYPT : IDEA_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            IDEA_cfb64_encrypt(in, out, (long)inlen, &ek, ivec, &num,
                               enc_op ? IDEA_ENCRYPT : IDEA_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "OFB") == 0) {
            IDEA_ofb64_encrypt(in, out, (long)inlen, &ek, ivec, &num);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    if (strncmp(cipher, "SEED-", 5) == 0) {
        SEED_KEY_SCHEDULE sk;
        int num = 0;

        if (keylen != 16 || ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        SEED_set_key(key, &sk);
        if (strcmp(mode, "ECB") == 0) {
            size_t i;

            if (inlen % 16 != 0)
                return -1;
            for (i = 0; i < inlen; i += 16)
                SEED_ecb_encrypt(in + i, out + i, &sk, enc_op ? 1 : 0);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 16 != 0 || ivlen != 16)
                return -1;
            SEED_cbc_encrypt(in, out, inlen, &sk, ivec, enc_op ? 1 : 0);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            if (ivlen != 16)
                return -1;
            SEED_cfb128_encrypt(in, out, inlen, &sk, ivec, &num, enc_op ? 1 : 0);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "OFB") == 0) {
            if (ivlen != 16)
                return -1;
            SEED_ofb128_encrypt(in, out, inlen, &sk, ivec, &num);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    if (strncmp(cipher, "CAMELLIA-", 9) == 0) {
        CAMELLIA_KEY ck;
        int num = 0;
        int bits;

        if (strncmp(cipher + 9, "128-", 4) == 0)
            bits = 128;
        else if (strncmp(cipher + 9, "192-", 4) == 0)
            bits = 192;
        else if (strncmp(cipher + 9, "256-", 4) == 0)
            bits = 256;
        else
            return -1;
        if (keylen != (size_t)bits / 8 || ivlen > sizeof(ivec))
            return -1;
        memcpy(ivec, iv, ivlen);
        if (Camellia_set_key(key, bits, &ck) != 0)
            return -1;
        if (strcmp(mode, "ECB") == 0) {
            size_t i;

            if (inlen % 16 != 0)
                return -1;
            for (i = 0; i < inlen; i += 16)
                Camellia_ecb_encrypt(in + i, out + i, &ck,
                                     enc_op ? CAMELLIA_ENCRYPT : CAMELLIA_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CBC") == 0) {
            if (inlen % 16 != 0 || ivlen != 16)
                return -1;
            Camellia_cbc_encrypt(in, out, inlen, &ck, ivec,
                                 enc_op ? CAMELLIA_ENCRYPT : CAMELLIA_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CFB") == 0) {
            if (ivlen != 16)
                return -1;
            Camellia_cfb128_encrypt(in, out, inlen, &ck, ivec, &num,
                                    enc_op ? CAMELLIA_ENCRYPT : CAMELLIA_DECRYPT);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "OFB") == 0) {
            if (ivlen != 16)
                return -1;
            Camellia_ofb128_encrypt(in, out, inlen, &ck, ivec, &num);
            *outlen = inlen;
            return 0;
        }
        if (strcmp(mode, "CTR") == 0) {
            unsigned char ecount[16];
            unsigned int ctr = 0;

            if (ivlen != 16)
                return -1;
            memset(ecount, 0, sizeof(ecount));
            Camellia_ctr128_encrypt(in, out, inlen, &ck, ivec, ecount, &ctr);
            *outlen = inlen;
            return 0;
        }
        return -1;
    }

    return -1;
}

/*
 * The key-wrap family: RFC 3394 (`id-aes*-wrap`) and RFC 5649 (`id-aes*-wrap-pad`). The
 * wrapping is driven through `CRYPTO_128_wrap`/`_unwrap`/`_wrap_pad`/`_unwrap_pad` with the
 * AES block cipher as the `block128_f`, which is exactly how the authority's own
 * `AES_wrap_key`/`AES_unwrap_key` are spelled over the same functions.
 */
static int ct_wrap(const char *cipher, int enc_op,
                   const unsigned char *key, size_t keylen,
                   const unsigned char *iv, size_t ivlen,
                   const unsigned char *in, size_t inlen,
                   unsigned char *out, size_t *outlen)
{
    AES_KEY enc, dck;
    int bits;
    size_t n;

    if (ivlen != 0 || strncmp(cipher, "id-aes", 6) != 0)
        return -1;
    if (strncmp(cipher + 6, "128", 3) == 0)
        bits = 128;
    else if (strncmp(cipher + 6, "192", 3) == 0)
        bits = 192;
    else if (strncmp(cipher + 6, "256", 3) == 0)
        bits = 256;
    else
        return -1;
    if (keylen != (size_t)bits / 8)
        return -1;

    if (strcmp(cipher + 9, "-wrap") != 0 && strcmp(cipher + 9, "-wrap-pad") != 0)
        return -1;

    if (enc_op) {
        if (AES_set_encrypt_key(key, bits, &enc) != 0)
            return -1;
        if (strcmp(cipher + 9, "-wrap") == 0)
            n = CRYPTO_128_wrap(&enc, NULL, out, in, inlen,
                                (block128_f)AES_encrypt);
        else
            n = CRYPTO_128_wrap_pad(&enc, NULL, out, in, inlen,
                                    (block128_f)AES_encrypt);
    } else {
        if (AES_set_decrypt_key(key, bits, &dck) != 0)
            return -1;
        if (strcmp(cipher + 9, "-wrap") == 0)
            n = CRYPTO_128_unwrap(&dck, NULL, out, in, inlen,
                                  (block128_f)AES_decrypt);
        else
            n = CRYPTO_128_unwrap_pad(&dck, NULL, out, in, inlen,
                                      (block128_f)AES_decrypt);
    }
    if (n == 0)
        return -1;
    *outlen = n;
    return 0;
}

/*
 * GCM: the AEAD arm. The output is `ciphertext || tag || accept || reject`, where the last
 * two bytes are the probe's own tag-verification answers (0x01 for the expected outcome).
 * Checking both arms on every vector is what makes a rejected tag a committed expectation
 * rather than a claim: the corpus's negative blocks carry `Result = CIPHERFINAL_ERROR` and are
 * skipped by the generator, so the reject path has to come from here.
 */
static int ct_gcm(const char *cipher, int enc_op,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *iv, size_t ivlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *in, size_t inlen,
                  unsigned char *out, size_t *outlen, size_t taglen)
{
    AES_KEY ek;
    GCM128_CONTEXT *ctx;
    unsigned char tag[16];
    unsigned char bad[16];
    unsigned char tmp[CT_MAX];
    int bits;
    int accept;
    int reject;

    if (enc_op != 1 || strncmp(cipher, "aes-", 4) != 0)
        return -1;
    if (strncmp(cipher + 4, "128-gcm", 7) == 0)
        bits = 128;
    else if (strncmp(cipher + 4, "192-gcm", 7) == 0)
        bits = 192;
    else if (strncmp(cipher + 4, "256-gcm", 7) == 0)
        bits = 256;
    else
        return -1;
    if (keylen != (size_t)bits / 8 || inlen > sizeof(tmp) || taglen > 16)
        return -1;
    if (AES_set_encrypt_key(key, bits, &ek) != 0)
        return -1;

    ctx = CRYPTO_gcm128_new(&ek, (block128_f)AES_encrypt);
    if (ctx == NULL)
        return -1;
    CRYPTO_gcm128_setiv(ctx, iv, ivlen);
    if (aadlen != 0)
        CRYPTO_gcm128_aad(ctx, aad, aadlen);
    if (CRYPTO_gcm128_encrypt(ctx, in, out, inlen) != 0) {
        CRYPTO_gcm128_release(ctx);
        return -1;
    }
    CRYPTO_gcm128_tag(ctx, tag, sizeof(tag));
    CRYPTO_gcm128_release(ctx);

    ctx = CRYPTO_gcm128_new(&ek, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv, ivlen);
    if (aadlen != 0)
        CRYPTO_gcm128_aad(ctx, aad, aadlen);
    CRYPTO_gcm128_decrypt(ctx, out, tmp, inlen);
    accept = CRYPTO_gcm128_finish(ctx, tag, sizeof(tag)) == 0;
    CRYPTO_gcm128_release(ctx);

    memcpy(bad, tag, sizeof(bad));
    bad[0] ^= 0x01;
    ctx = CRYPTO_gcm128_new(&ek, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(ctx, iv, ivlen);
    if (aadlen != 0)
        CRYPTO_gcm128_aad(ctx, aad, aadlen);
    CRYPTO_gcm128_decrypt(ctx, out, tmp, inlen);
    reject = CRYPTO_gcm128_finish(ctx, bad, sizeof(bad)) != 0;
    CRYPTO_gcm128_release(ctx);

    if (memcmp(tmp, in, inlen) != 0)
        return -1;
    memcpy(out + inlen, tag, taglen);
    out[inlen + taglen] = accept ? 1u : 0u;
    out[inlen + taglen + 1] = reject ? 1u : 0u;
    *outlen = inlen + taglen + 2;
    return 0;
}

/*
 * The CCM arm's **provider branch**, for the families whose schedule the driver cannot reach.
 *
 * `CRYPTO_ccm128_init` takes a `block128_f` over the row's own key schedule, and the authority
 * exports no ARIA or SM4 primitive at all -- so for these two families the only schedule reachable
 * from the distribution shell is the row's own, through `EVP_CIPHER_fetch`. Everything else is the
 * same record: the tag is read back through `EVP_CTRL_AEAD_GET_TAG`, and the two answer bytes come
 * from re-running the decrypt with that tag and with a one-bit flip of it, so a vector's
 * expectation is still entirely the corpus's own bytes and this arm still asks the construction
 * question rather than the parity one. This is D267's precedent -- SM4's rows reached this court
 * through the provider because they publish no low-level API -- applied to the AEAD arm.
 */
static int ct_ccm_evp(const char *cipher,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen,
                      const unsigned char *aad, size_t aadlen,
                      const unsigned char *in, size_t inlen,
                      unsigned char *out, size_t *outlen, size_t m)
{
    EVP_CIPHER *c;
    EVP_CIPHER_CTX *ctx;
    unsigned char tag[16], bad[16], back[CT_MAX];
    int l = 0, f = 0, al = 0, bl = 0;
    int accept = 0, reject = 0;

    if (m < 4 || m > 16 || (m & 1) != 0 || ivlen > INT_MAX || inlen > INT_MAX
        || keylen > INT_MAX || aadlen > INT_MAX)
        return -1;
    c = EVP_CIPHER_fetch(NULL, cipher, NULL);
    if (c == NULL)
        return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        EVP_CIPHER_free(c);
        return -1;
    }

    /* Encrypt, and read the tag the construction produced. */
    if (EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, (int)ivlen, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)m, NULL) != 1
        || EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL) != 1
        || EVP_EncryptUpdate(ctx, NULL, &al, NULL, (int)inlen) != 1
        || (aadlen != 0 && EVP_EncryptUpdate(ctx, NULL, &al, aad, (int)aadlen) != 1)
        || EVP_EncryptUpdate(ctx, out, &l, in, (int)inlen) != 1
        || EVP_EncryptFinal_ex(ctx, out + l, &f) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)m, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
        return -1;
    }

    /*
     * The two answers. The `accept` arm decrypts under the tag and must return the plaintext; the
     * `reject` arm decrypts under a one-bit flip of it and must refuse. Each is a fresh init on the
     * same context, because a CCM context carries the operation's state.
     */
    memcpy(bad, tag, m);
    bad[0] ^= 0x01;

    memset(back, 0, sizeof(back));
    bl = 0;
    accept = (EVP_DecryptInit_ex2(ctx, c, NULL, NULL, NULL) == 1
              && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, (int)ivlen, NULL) == 1
              && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)m, (void *)tag) == 1
              && EVP_DecryptInit_ex2(ctx, NULL, key, iv, NULL) == 1
              && EVP_DecryptUpdate(ctx, NULL, &al, NULL, (int)inlen) == 1
              && (aadlen == 0 || EVP_DecryptUpdate(ctx, NULL, &al, aad, (int)aadlen) == 1)
              && EVP_DecryptUpdate(ctx, back, &bl, out, l + f) == 1
              && EVP_DecryptFinal_ex(ctx, back + bl, &f) == 1
              && bl == (int)inlen
              && memcmp(back, in, inlen) == 0)
                 ? 1
                 : 0;

    /*
     * `reject`: a one-bit flip in the tag must be refused. **The refusal lands on the payload
     * update, not on the final** -- the low-level arm's per-step record reads `1,1,1,1,1,1,0,-1`
     * on the authority for every family -- so the answer is that the update returned 0 and wrote
     * nothing.
     */
    memset(back, 0, sizeof(back));
    reject = 0;
    if (EVP_DecryptInit_ex2(ctx, c, NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, (int)ivlen, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)m, (void *)bad) == 1
        && EVP_DecryptInit_ex2(ctx, NULL, key, iv, NULL) == 1
        && EVP_DecryptUpdate(ctx, NULL, &al, NULL, (int)inlen) == 1
        && (aadlen == 0 || EVP_DecryptUpdate(ctx, NULL, &al, aad, (int)aadlen) == 1)) {
        bl = 0;
        reject = EVP_DecryptUpdate(ctx, back, &bl, out, l + f) != 1 && bl == 0;
    }

    memcpy(out + inlen, tag, m);
    out[inlen + m] = (unsigned char)(accept ? 1u : 0u);
    out[inlen + m + 1] = (unsigned char)(reject ? 1u : 0u);
    *outlen = inlen + m + 2;
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return 0;
}

/*
 * CCM: the second AEAD arm, with the same `ciphertext || tag || accept || reject` answer as
 * `ct_gcm`. `M` is the vector's tag length and `L = 15 - ivlen`; the CAVS corpus uses every even
 * `M` in [4,16] and every `L` in [2,8], so both are read from the vector rather than fixed.
 * `CCM128_CONTEXT` is opaque in the public header, so the storage is a 128-byte aligned buffer
 * which the library fills with its own context and the probe never reads back.
 */
static int ct_ccm(const char *cipher, int enc_op,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *iv, size_t ivlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *in, size_t inlen,
                  unsigned char *out, size_t *outlen, size_t taglen)
{
    AES_KEY ek;
    union {
        unsigned char bytes[128];
        unsigned long long align;
    } store;
    CCM128_CONTEXT *ctx = (CCM128_CONTEXT *)&store;
    unsigned char tag[16], bad[16], got[16];
    unsigned char tmp[CT_MAX];
    int bits;
    size_t m = taglen, l;
    int accept, reject;

    if (enc_op != 1)
        return -1;
    /*
     * The families with no low-level primitive go through the provider branch; the AES rows keep
     * the low-level one, which is what makes the CAVS expectation a construction claim rather than
     * a re-run of the provider.
     */
    if (strncmp(cipher, "aes-", 4) != 0) {
        size_t cl = strlen(cipher);

        /*
         * The corpus spells the AEAD names in lower case for AES and in upper case for ARIA and
         * SM4, so the suffix test is case-insensitive. Getting that wrong is silent in the worst
         * way: this arm refuses, the caller falls through to the plain provider path, and the
         * answer is a bare ciphertext that fails every vector without saying why.
         */
        if (cl < 4
            || (cipher[cl - 4] != '-')
            || (cipher[cl - 3] != 'c' && cipher[cl - 3] != 'C')
            || (cipher[cl - 2] != 'c' && cipher[cl - 2] != 'C')
            || (cipher[cl - 1] != 'm' && cipher[cl - 1] != 'M'))
            return -1;
        return ct_ccm_evp(cipher, key, keylen, iv, ivlen, aad, aadlen, in, inlen,
                          out, outlen, taglen);
    }
    if (strncmp(cipher + 4, "128-ccm", 7) == 0)
        bits = 128;
    else if (strncmp(cipher + 4, "192-ccm", 7) == 0)
        bits = 192;
    else if (strncmp(cipher + 4, "256-ccm", 7) == 0)
        bits = 256;
    else
        return -1;
    if (keylen != (size_t)bits / 8 || inlen > sizeof(tmp))
        return -1;
    if (m < 4 || m > 16 || (m & 1) != 0)
        return -1;
    if (ivlen < 7 || ivlen > 13)
        return -1;
    l = 15 - ivlen;
    if (AES_set_encrypt_key(key, bits, &ek) != 0)
        return -1;

    memset(&store, 0, sizeof(store));
    CRYPTO_ccm128_init(ctx, (unsigned)m, (unsigned)l, &ek, (block128_f)AES_encrypt);
    if (CRYPTO_ccm128_setiv(ctx, iv, ivlen, inlen) != 0)
        return -1;
    if (aadlen != 0)
        CRYPTO_ccm128_aad(ctx, aad, aadlen);
    if (CRYPTO_ccm128_encrypt(ctx, in, out, inlen) != 0)
        return -1;
    if (CRYPTO_ccm128_tag(ctx, tag, m) != m)
        return -1;

    memset(&store, 0, sizeof(store));
    CRYPTO_ccm128_init(ctx, (unsigned)m, (unsigned)l, &ek, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, iv, ivlen, inlen);
    if (aadlen != 0)
        CRYPTO_ccm128_aad(ctx, aad, aadlen);
    if (CRYPTO_ccm128_decrypt(ctx, out, tmp, inlen) != 0)
        return -1;
    accept = CRYPTO_ccm128_tag(ctx, got, m) == m && memcmp(got, tag, m) == 0;

    memcpy(bad, tag, m);
    bad[0] ^= 0x01;
    memset(&store, 0, sizeof(store));
    CRYPTO_ccm128_init(ctx, (unsigned)m, (unsigned)l, &ek, (block128_f)AES_encrypt);
    CRYPTO_ccm128_setiv(ctx, iv, ivlen, inlen);
    if (aadlen != 0)
        CRYPTO_ccm128_aad(ctx, aad, aadlen);
    if (CRYPTO_ccm128_decrypt(ctx, out, tmp, inlen) != 0)
        return -1;
    reject = CRYPTO_ccm128_tag(ctx, got, m) == m && memcmp(got, bad, m) != 0;

    if (memcmp(tmp, in, inlen) != 0)
        return -1;
    memcpy(out + inlen, tag, m);
    out[inlen + m] = accept ? 1u : 0u;
    out[inlen + m + 1] = reject ? 1u : 0u;
    *outlen = inlen + m + 2;
    return 0;
}

/*
 * XTS: a data unit of one block or more, with a caller-populated context. The vector's key is
 * the two concatenated AES keys, the IV is the sixteen-byte initial tweak, and the ciphertext is
 * the whole answer (no tag). The direction comes from the vector, and for decryption the caller
 * hands `block1` the data cipher's *decrypt* function (`crypto/evp/e_aes.c:303`).
 */
typedef struct {
    void *key1;
    void *key2;
    block128_f block1;
    block128_f block2;
} ct_xts_ctx;

static void ct_xts_dec_block(const unsigned char *in, unsigned char *out, const void *key)
{
    AES_decrypt(in, out, (const AES_KEY *)key);
}

static int ct_xts(const char *cipher, int enc_op,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *iv, size_t ivlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *in, size_t inlen,
                  unsigned char *out, size_t *outlen, size_t taglen)
{
    AES_KEY ek1, ek2, dk1;
    ct_xts_ctx x;
    int bits;

    (void)aad;
    (void)aadlen;
    if (strncmp(cipher, "aes-", 4) != 0)
        return -1;
    if (strncmp(cipher + 4, "128-xts", 7) == 0)
        bits = 128;
    else if (strncmp(cipher + 4, "256-xts", 7) == 0)
        bits = 256;
    else
        return -1;
    if (ivlen != 16 || taglen != 0 || inlen < 16)
        return -1;
    if (keylen != 2 * (size_t)bits / 8)
        return -1;
    if (AES_set_encrypt_key(key, bits, &ek1) != 0
        || AES_set_encrypt_key(key + bits / 8, bits, &ek2) != 0
        || AES_set_decrypt_key(key, bits, &dk1) != 0)
        return -1;

    x.key1 = enc_op ? (void *)&ek1 : (void *)&dk1;
    x.key2 = (void *)&ek2;
    x.block1 = enc_op ? (block128_f)AES_encrypt : (block128_f)ct_xts_dec_block;
    x.block2 = (block128_f)AES_encrypt;
    if (CRYPTO_xts128_encrypt((const XTS128_CONTEXT *)&x, iv, in, out, inlen, enc_op) != 0)
        return -1;
    *outlen = inlen;
    return 0;
}

/*
 * OCB: the third AEAD arm, with the same `ciphertext || tag || accept || reject` answer as
 * `ct_gcm`. `OCB128_CONTEXT` is opaque in the public header and is allocated by the library
 * (`CRYPTO_ocb128_new`), so the probe only ever holds the pointer. `M` is the vector's tag
 * length and the nonce length (1..15) is the vector's; `setiv` refuses anything else. RFC 7253
 * is the primary source and `evpciph_aes_ocb.txt` is the corpus it is mirrored through.
 */
static int ct_ocb(const char *cipher, int enc_op,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *iv, size_t ivlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *in, size_t inlen,
                  unsigned char *out, size_t *outlen, size_t taglen)
{
    AES_KEY ek, dk;
    OCB128_CONTEXT *ctx;
    unsigned char tag[16], bad[16];
    unsigned char tmp[CT_MAX];
    int bits;
    size_t m = taglen;
    int accept, reject;

    if (enc_op != 1 || strncmp(cipher, "aes-", 4) != 0)
        return -1;
    if (strncmp(cipher + 4, "128-ocb", 7) == 0)
        bits = 128;
    else if (strncmp(cipher + 4, "192-ocb", 7) == 0)
        bits = 192;
    else if (strncmp(cipher + 4, "256-ocb", 7) == 0)
        bits = 256;
    else
        return -1;
    if (keylen != (size_t)bits / 8 || inlen > sizeof(tmp))
        return -1;
    if (m < 1 || m > 16 || ivlen < 1 || ivlen > 15)
        return -1;
    if (AES_set_encrypt_key(key, bits, &ek) != 0 || AES_set_decrypt_key(key, bits, &dk) != 0)
        return -1;

    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    if (ctx == NULL)
        return -1;
    if (CRYPTO_ocb128_setiv(ctx, iv, ivlen, m) != 1 || (aadlen != 0 && CRYPTO_ocb128_aad(ctx, aad, aadlen) != 1)
        || CRYPTO_ocb128_encrypt(ctx, in, out, inlen) != 1
        || CRYPTO_ocb128_tag(ctx, tag, m) != 1) {
        CRYPTO_ocb128_cleanup(ctx);
        return -1;
    }
    CRYPTO_ocb128_cleanup(ctx);

    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv, ivlen, m);
    if (aadlen != 0)
        CRYPTO_ocb128_aad(ctx, aad, aadlen);
    CRYPTO_ocb128_decrypt(ctx, out, tmp, inlen);
    accept = CRYPTO_ocb128_finish(ctx, tag, m) == 0;
    CRYPTO_ocb128_cleanup(ctx);

    memcpy(bad, tag, m);
    bad[0] ^= 0x01;
    ctx = CRYPTO_ocb128_new(&ek, &dk, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ctx, iv, ivlen, m);
    if (aadlen != 0)
        CRYPTO_ocb128_aad(ctx, aad, aadlen);
    CRYPTO_ocb128_decrypt(ctx, out, tmp, inlen);
    reject = CRYPTO_ocb128_finish(ctx, bad, m) != 0;
    CRYPTO_ocb128_cleanup(ctx);

    if (memcmp(tmp, in, inlen) != 0)
        return -1;
    memcpy(out + inlen, tag, m);
    out[inlen + m] = accept ? 1u : 0u;
    out[inlen + m + 1] = reject ? 1u : 0u;
    *outlen = inlen + m + 2;
    return 0;
}

/*
 * CTS: `AES-*-CBC-CTS` is three constructions under one name. CS1 is the NIST variant
 * (`CRYPTO_nistcts128_*`), CS3 the Kerberos one (`CRYPTO_cts128_*`), and CS2 is CS3 for a
 * partial block and plain CBC for an aligned one (`cipher_cts.c:301-325`). The corpus's
 * `CTSMode` line chooses the variant. A sixteen-byte CS3 message is the one-block special
 * case, which the authority handles with a plain CBC block.
 */
static int ct_cts(const char *cipher, const char *ctsmode, int enc_op,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *iv, size_t ivlen,
                  const unsigned char *in, size_t inlen,
                  unsigned char *out, size_t *outlen)
{
    AES_KEY aenc, adck;
    CAMELLIA_KEY ckey;
    unsigned char ivec[16];
    const char *mode = (ctsmode != NULL && ctsmode[0] != '\0') ? ctsmode : "CS1";
    int is_aes, bits;
    size_t n;

    if (ivlen != 16 || inlen < 16)
        return -1;
    if (strncmp(cipher, "AES-", 4) == 0 && strstr(cipher, "-CBC-CTS") != NULL) {
        is_aes = 1;
        bits = atoi(cipher + 4);
    } else if (strncmp(cipher, "CAMELLIA-", 9) == 0 && strstr(cipher, "-CBC-CTS") != NULL) {
        is_aes = 0;
        bits = atoi(cipher + 9);
    } else {
        return -1;
    }
    if (bits != 128 && bits != 192 && bits != 256)
        return -1;
    if (keylen != (size_t)bits / 8)
        return -1;
    memcpy(ivec, iv, 16);

    if (is_aes) {
        if (enc_op) {
            if (AES_set_encrypt_key(key, bits, &aenc) != 0)
                return -1;
        } else if (AES_set_decrypt_key(key, bits, &adck) != 0) {
            return -1;
        }
    } else if (Camellia_set_key(key, bits, &ckey) != 0) {
        return -1;
    }

    if (is_aes) {
        cbc128_f cbc = (cbc128_f)AES_cbc_encrypt;
        const void *keyp = enc_op ? (const void *)&aenc : (const void *)&adck;

        if (strcmp(mode, "CS1") == 0) {
            n = enc_op ? CRYPTO_nistcts128_encrypt(in, out, inlen, keyp, ivec, cbc)
                       : CRYPTO_nistcts128_decrypt(in, out, inlen, keyp, ivec, cbc);
        } else if (strcmp(mode, "CS3") == 0 && inlen == 16) {
            AES_cbc_encrypt(in, out, 16, keyp, ivec, enc_op);
            n = 16;
        } else if (strcmp(mode, "CS2") == 0 && inlen % 16 == 0) {
            AES_cbc_encrypt(in, out, inlen, keyp, ivec, enc_op);
            n = inlen;
        } else {
            n = enc_op ? CRYPTO_cts128_encrypt(in, out, inlen, keyp, ivec, cbc)
                       : CRYPTO_cts128_decrypt(in, out, inlen, keyp, ivec, cbc);
        }
    } else {
        cbc128_f cbc = (cbc128_f)Camellia_cbc_encrypt;
        const void *keyp = (const void *)&ckey;

        if (strcmp(mode, "CS1") == 0) {
            n = enc_op ? CRYPTO_nistcts128_encrypt(in, out, inlen, keyp, ivec, cbc)
                       : CRYPTO_nistcts128_decrypt(in, out, inlen, keyp, ivec, cbc);
        } else if (strcmp(mode, "CS3") == 0 && inlen == 16) {
            Camellia_cbc_encrypt(in, out, 16, &ckey, ivec, enc_op);
            n = 16;
        } else if (strcmp(mode, "CS2") == 0 && inlen % 16 == 0) {
            Camellia_cbc_encrypt(in, out, inlen, &ckey, ivec, enc_op);
            n = inlen;
        } else {
            n = enc_op ? CRYPTO_cts128_encrypt(in, out, inlen, keyp, ivec, cbc)
                       : CRYPTO_cts128_decrypt(in, out, inlen, keyp, ivec, cbc);
        }
    }
    if (n == 0)
        return -1;
    *outlen = n;
    return 0;
}


/*
 * **The provider path, used by the rows that have no low-level API at all.**
 *
 * Every arm above drives a low-level function -- `AES_cbc_encrypt`, `DES_ede3_cbc_encrypt`,
 * `SEED_ecb_encrypt` -- because that is the surface those algorithms publish. SM4 publishes **none**:
 * `nm -D libcrypto.so.3` lists no `SM4_*` symbol and `include/crypto/sm4.h` is an internal header, so
 * the five `SM4-*` rows exist *only* as provider registrations and the only way to reach them is
 * `EVP_CIPHER_fetch`. ARIA is the same.
 *
 * This arm is still **candidate-only**, which is the court's whole property: it fetches through the
 * candidate's own distribution shell and compares against the standard's bytes. What it adds over
 * `RT-CIPHER` is the oracle -- `RT-CIPHER` proves the row behaves as the authority's does, and this
 * proves the bytes are GB/T 32907-2016's.
 *
 * Padding is turned **off**, because the corpus's vectors are block-aligned plaintexts and a padded
 * final would add a block the expected ciphertext does not have.
 */
static int ct_evp(const char *cipher, int enc_op,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *iv, size_t ivlen,
                  const unsigned char *in, size_t inlen,
                  unsigned char *out, size_t *outlen)
{
    EVP_CIPHER *c;
    EVP_CIPHER_CTX *ctx;
    int l1 = 0, l2 = 0, ok;

    if (cipher == NULL || keylen > INT_MAX || inlen > INT_MAX)
        return -1;
    c = EVP_CIPHER_fetch(NULL, cipher, NULL);
    if (c == NULL)
        return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        EVP_CIPHER_free(c);
        return -1;
    }
    ok = enc_op ? EVP_EncryptInit_ex(ctx, c, NULL, key, ivlen ? iv : NULL)
                : EVP_DecryptInit_ex(ctx, c, NULL, key, ivlen ? iv : NULL);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ok = enc_op ? EVP_EncryptUpdate(ctx, out, &l1, in, (int)inlen)
                : EVP_DecryptUpdate(ctx, out, &l1, in, (int)inlen);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
        return -1;
    }
    *outlen = (size_t)l1;
    ok = enc_op ? EVP_EncryptFinal_ex(ctx, out + l1, &l2)
                : EVP_DecryptFinal_ex(ctx, out + l1, &l2);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
        return -1;
    }
    *outlen += (size_t)l2;
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return 0;
}

static int ct_cipher(const char *cipher, const char *operation,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen,
                     const unsigned char *aad, size_t aadlen,
                     const unsigned char *in, size_t inlen,
                     unsigned char *out, size_t *outlen, size_t taglen,
                     const char *ctsmode)
{
    int enc_op = strcmp(operation, "ENCRYPT") == 0;

    if (ct_gcm(cipher, enc_op, key, keylen, iv, ivlen, aad, aadlen,
               in, inlen, out, outlen, taglen) == 0)
        return 0;
    if (ct_ccm(cipher, enc_op, key, keylen, iv, ivlen, aad, aadlen,
               in, inlen, out, outlen, taglen) == 0)
        return 0;
    if (ct_xts(cipher, enc_op, key, keylen, iv, ivlen, aad, aadlen,
               in, inlen, out, outlen, taglen) == 0)
        return 0;
    if (ct_ocb(cipher, enc_op, key, keylen, iv, ivlen, aad, aadlen,
               in, inlen, out, outlen, taglen) == 0)
        return 0;
    if (ct_cts(cipher, ctsmode, enc_op, key, keylen, iv, ivlen,
               in, inlen, out, outlen) == 0)
        return 0;
    if (ct_wrap(cipher, enc_op, key, keylen, iv, ivlen, in, inlen, out, outlen) == 0)
        return 0;
    if (ct_aes_rc4(cipher, enc_op, key, keylen, iv, ivlen, in, inlen, out, outlen) == 0)
        return 0;
    if (ct_legacy(cipher, enc_op, key, keylen, iv, ivlen, in, inlen, out, outlen) == 0)
        return 0;
    /* Last resort: the provider path, for the rows that publish no low-level API (SM4, and ARIA
     * when it lands). A name nothing recognises still refuses. */
    return ct_evp(cipher, enc_op, key, keylen, iv, ivlen, in, inlen, out, outlen);
}

int main(int argc, char **argv)
{
    FILE *fp;
    char line[CT_LINE];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 2) {
        fprintf(stderr, "usage: %s <calls.tsv>\n", argv[0]);
        return 2;
    }
    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror(argv[1]);
        return 2;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *fields[8];
        int nf = 0;
        char *p = line;
        unsigned char key[64], iv[64], aad[CT_MAX], in[CT_MAX], out[CT_MAX + 64];
        size_t keylen = 0, ivlen = 0, aadlen = 0, inlen = 0, outlen = 0;
        size_t taglen = 0;
        const char *ctsmode = "";
        long index;
        int rc;

        while (nf < 7) {
            char *tab = strchr(p, '\t');

            if (tab == NULL)
                break;
            *tab = '\0';
            fields[nf++] = p;
            p = tab + 1;
        }
        if (nf < 7)
            continue;
        fields[nf++] = p;
        if (nf < 8)
            continue;
        {
            /* field[7] is `taglen`, and the optional ninth column is the CTS mode. */
            char *tab = strchr(fields[7], '\t');
            char *nl;

            if (tab != NULL) {
                *tab = '\0';
                ctsmode = tab + 1;
            }
            nl = strchr(tab != NULL ? ctsmode : fields[7], '\n');
            if (nl != NULL)
                *nl = '\0';
        }
        index = strtol(fields[0], NULL, 10);
        taglen = (size_t)strtol(fields[7], NULL, 10);
        if (ct_unhex(fields[3], key, sizeof(key), &keylen) != 0
            || ct_unhex(fields[4], iv, sizeof(iv), &ivlen) != 0
            || ct_unhex(fields[5], in, sizeof(in), &inlen) != 0
            || ct_unhex(fields[6], aad, sizeof(aad), &aadlen) != 0) {
            printf("%ld\terr\tbad-hex\n", index);
            continue;
        }
        rc = ct_cipher(fields[1], fields[2], key, keylen, iv, ivlen, aad, aadlen,
                       in, inlen, out, &outlen, taglen, ctsmode);
        if (rc != 0) {
            printf("%ld\terr\trefused\n", index);
            continue;
        }
        {
            char hex[2 * (CT_MAX + 64) + 1];

            ct_hex(hex, out, outlen);
            printf("%ld\tok\t%s\n", index, hex);
        }
    }
    fclose(fp);
    return 0;
}
