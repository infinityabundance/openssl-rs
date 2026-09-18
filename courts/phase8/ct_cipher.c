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
#include <openssl/rc4.h>

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

/* Run one vector. Returns 0 on success with the output in `out`/`outlen`. */
static int ct_cipher(const char *cipher, const char *operation,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen,
                     const unsigned char *in, size_t inlen,
                     unsigned char *out, size_t *outlen)
{
    AES_KEY enc, dck;
    unsigned char ivec[32];
    int bits;
    int enc_op = strcmp(operation, "ENCRYPT") == 0;

    /* RC4 is a stream cipher: no block, no IV, and one call transforms any number of bytes. */
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
