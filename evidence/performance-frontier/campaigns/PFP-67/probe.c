/*
 * PFP-67 — OPENSSL_ia32cap compatibility probe.
 *
 * The same source is compiled twice: once against the admitted authority's static
 * `libcrypto.a`, once against the candidate's static archive. Every line is a function of
 * the library under test and the process environment alone (no address, clock or duration),
 * so the transcript is reproducible for a given `OPENSSL_ia32cap` value.
 *
 * The output bytes are the compatibility observable. The authority's capability words are
 * additionally reported when its archive is linked (`OPENSSL_ia32cap_P` is `.hidden`, so a
 * dynamic link would not reach it); on the candidate those lines are `n/a`, and its actual
 * dispatch decision comes from the Rust `runtime::cpu` child transcript instead.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/sha.h>

#if defined(__x86_64__) || defined(__i386__)
# define PFP67_X86 1
#else
# define PFP67_X86 0
#endif

#if PFP67_X86
/* Weak so the probe links on either side; only the authority's static archive defines it. */
extern unsigned int OPENSSL_ia32cap_P[] __attribute__((weak));
#endif

static const unsigned char KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const unsigned char IV[16] = {
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
};
static const unsigned char PT[32] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
};

static void hex(const char *key, const unsigned char *b, size_t n)
{
    printf("%s=", key);
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

int main(void)
{
    unsigned int bits = 0;

#if PFP67_X86
    if (OPENSSL_ia32cap_P != NULL) {
        unsigned int w0 = OPENSSL_ia32cap_P[0];
        unsigned int w1 = OPENSSL_ia32cap_P[1];
        unsigned int w2 = OPENSSL_ia32cap_P[2];
        unsigned int w3 = OPENSSL_ia32cap_P[3];
        printf("cap.word0=0x%08x\n", w0);
        printf("cap.word1=0x%08x\n", w1);
        printf("cap.word2=0x%08x\n", w2);
        printf("cap.word3=0x%08x\n", w3);
        printf("cap.aes=%u\n", (w1 >> 25) & 1u);
        printf("cap.pclmul=%u\n", (w1 >> 1) & 1u);
        printf("cap.avx=%u\n", (w1 >> 28) & 1u);
        printf("cap.avx2=%u\n", (w2 >> 5) & 1u);
        printf("cap.sha=%u\n", (w2 >> 29) & 1u);
        printf("cap.vaes=%u\n", (w3 >> 9) & 1u);
        printf("cap.vpclmul=%u\n", (w3 >> 10) & 1u);
        bits = 1;
    } else {
        printf("cap.word0=n/a\ncap.word1=n/a\ncap.word2=n/a\ncap.word3=n/a\n");
        printf("cap.aes=n/a\ncap.pclmul=n/a\ncap.avx=n/a\ncap.avx2=n/a\n");
        printf("cap.sha=n/a\ncap.vaes=n/a\ncap.vpclmul=n/a\n");
    }
#else
    printf("cap.word0=n/a\ncap.word1=n/a\ncap.word2=n/a\ncap.word3=n/a\n");
    printf("cap.aes=n/a\ncap.pclmul=n/a\ncap.avx=n/a\ncap.avx2=n/a\n");
    printf("cap.sha=n/a\ncap.vaes=n/a\ncap.vpclmul=n/a\n");
#endif
    (void)bits;

    AES_KEY ks;
    if (AES_set_encrypt_key(KEY, 128, &ks) != 0) {
        printf("probe.key=fail\n");
        return 1;
    }

    {
        unsigned char one[16];
        AES_encrypt(PT, one, &ks);
        hex("out.aes_encrypt", one, sizeof one);
    }

    {
        unsigned char cbc[32];
        unsigned char iv[16];
        memcpy(iv, IV, sizeof iv);
        AES_cbc_encrypt(PT, cbc, sizeof cbc, &ks, iv, AES_ENCRYPT);
        hex("out.aes_cbc", cbc, sizeof cbc);
    }

    {
        unsigned char ctr[32];
        unsigned char iv[16];
        unsigned char ecount[16];
        unsigned int num = 0;
        memcpy(iv, IV, sizeof iv);
        CRYPTO_ctr128_encrypt(PT, ctr, sizeof ctr, &ks, iv, ecount, &num,
                              (block128_f)AES_encrypt);
        hex("out.aes_ctr", ctr, sizeof ctr);
    }

    {
        unsigned char gcm[32];
        unsigned char tag[16];
        unsigned char both[48];
        GCM128_CONTEXT *ctx = CRYPTO_gcm128_new(&ks, (block128_f)AES_encrypt);
        if (ctx == NULL) {
            printf("probe.gcm=fail\n");
            return 1;
        }
        CRYPTO_gcm128_setiv(ctx, IV, sizeof IV);
        CRYPTO_gcm128_encrypt(ctx, PT, gcm, sizeof gcm);
        (void)CRYPTO_gcm128_finish(ctx, NULL, 0);
        CRYPTO_gcm128_tag(ctx, tag, sizeof tag);
        CRYPTO_gcm128_release(ctx);
        memcpy(both, gcm, sizeof gcm);
        memcpy(both + sizeof gcm, tag, sizeof tag);
        hex("out.aes_gcm", both, sizeof both);
    }

    {
        unsigned char md[32];
        SHA256(PT, sizeof PT, md);
        hex("out.sha256", md, sizeof md);
    }

    printf("sel.cbc_hmac_sha1_128_null=%d\n", EVP_aes_128_cbc_hmac_sha1() == NULL);
    printf("sel.cbc_hmac_sha1_256_null=%d\n", EVP_aes_256_cbc_hmac_sha1() == NULL);
    printf("sel.cbc_hmac_sha256_128_null=%d\n", EVP_aes_128_cbc_hmac_sha256() == NULL);
    printf("sel.cbc_hmac_sha256_256_null=%d\n", EVP_aes_256_cbc_hmac_sha256() == NULL);

    {
        const char *cpuinfo = OpenSSL_version(OPENSSL_CPU_INFO);
        printf("api.cpuinfo=%s\n", cpuinfo != NULL ? cpuinfo : "");
        printf("api.cpu_settings_null=%d\n", OPENSSL_info(1008) == NULL);
    }

    printf("probe.done=1\n");
    return 0;
}
