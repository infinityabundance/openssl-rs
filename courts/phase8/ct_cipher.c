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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/des.h>
#include <openssl/idea.h>
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

    return -1;
}

static int ct_cipher(const char *cipher, const char *operation,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen,
                     const unsigned char *in, size_t inlen,
                     unsigned char *out, size_t *outlen)
{
    int enc_op = strcmp(operation, "ENCRYPT") == 0;

    if (ct_aes_rc4(cipher, enc_op, key, keylen, iv, ivlen, in, inlen, out, outlen) == 0)
        return 0;
    return ct_legacy(cipher, enc_op, key, keylen, iv, ivlen, in, inlen, out, outlen);
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
        unsigned char key[64], iv[64], in[CT_MAX], out[CT_MAX + 64];
        size_t keylen = 0, ivlen = 0, inlen = 0, outlen = 0;
        long index;
        int rc;

        while (nf < 5) {
            char *tab = strchr(p, '\t');

            if (tab == NULL)
                break;
            *tab = '\0';
            fields[nf++] = p;
            p = tab + 1;
        }
        if (nf < 5)
            continue;
        fields[nf++] = p;
        if (nf < 6)
            continue;
        {
            char *nl = strchr(fields[5], '\n');

            if (nl != NULL)
                *nl = '\0';
        }
        index = strtol(fields[0], NULL, 10);
        if (ct_unhex(fields[3], key, sizeof(key), &keylen) != 0
            || ct_unhex(fields[4], iv, sizeof(iv), &ivlen) != 0
            || ct_unhex(fields[5], in, sizeof(in), &inlen) != 0) {
            printf("%ld\terr\tbad-hex\n", index);
            continue;
        }
        rc = ct_cipher(fields[1], fields[2], key, keylen, iv, ivlen, in, inlen,
                       out, &outlen);
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
