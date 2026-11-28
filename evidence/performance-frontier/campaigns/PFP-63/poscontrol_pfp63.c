/*
 * poscontrol_pfp63.c — PFP-63 hardware truth and instruction-level positive controls.
 *
 * Reports the CPUID bits and the OS-enabled state (XCR0) for the extensions the
 * task names, then *executes* the intrinsics the implementation uses and checks
 * their output against an independent reference:
 *
 *   aeskeygenassist + aesenc + aesenclast   FIPS-197 C.1 AES-128 ciphertext
 *   pclmulqdq                               software carry-less multiply
 *   vaes (256-bit, if OS-enabled)           two independent aesenc results
 *   vpclmulqdq (256-bit, if OS-enabled)     two independent pclmul results
 *
 * Exit status is non-zero if a control that reported available then failed.
 */
#include <cpuid.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int fails;

static void cpuid1(unsigned *a, unsigned *b, unsigned *c, unsigned *d)
{
    __cpuid_count(1, 0, *a, *b, *c, *d);
}

static void cpuid7(unsigned *a, unsigned *b, unsigned *c, unsigned *d)
{
    __cpuid_count(7, 0, *a, *b, *c, *d);
}

static uint64_t xcr0(void)
{
    unsigned lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((uint64_t)hi << 32) | lo;
}

static void hex16(const char *tag, const unsigned char *p)
{
    printf("%s=", tag);
    for (int i = 0; i < 16; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void expand_step(__m128i *rk, int i)
{
    __m128i t;

    switch (i) {
#define EXPAND(N, RC)                                        \
    case N:                                                   \
        t = _mm_aeskeygenassist_si128(rk[N - 1], RC);         \
        break;
        EXPAND(1, 0x01) EXPAND(2, 0x02) EXPAND(3, 0x04)
        EXPAND(4, 0x08) EXPAND(5, 0x10) EXPAND(6, 0x20)
        EXPAND(7, 0x40) EXPAND(8, 0x80) EXPAND(9, 0x1b)
        EXPAND(10, 0x36)
#undef EXPAND
    default:
        return;
    }
    t = _mm_shuffle_epi32(t, _MM_SHUFFLE(3, 3, 3, 3));
    __m128i k = rk[i - 1];
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    rk[i] = _mm_xor_si128(k, t);
}

static void aes_control(void)
{
    const unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const unsigned char pt[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const unsigned char want[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    };
    __m128i rk[11];
    unsigned char out[16];

    rk[0] = _mm_loadu_si128((const __m128i *)key);
    for (int i = 1; i <= 10; i++)
        expand_step(rk, i);

    __m128i s = _mm_loadu_si128((const __m128i *)pt);
    s = _mm_xor_si128(s, rk[0]);
    for (int i = 1; i < 10; i++)
        s = _mm_aesenc_si128(s, rk[i]);
    s = _mm_aesenclast_si128(s, rk[10]);
    _mm_storeu_si128((__m128i *)out, s);

    hex16("aes_control_out", out);
    if (memcmp(out, want, 16) != 0) {
        printf("aes_control=FAIL\n");
        fails++;
    } else {
        printf("aes_control=PASS (FIPS-197 C.1)\n");
    }
}

static void software_clmul(uint64_t x, uint64_t y, uint64_t *lo, uint64_t *hi)
{
    uint64_t l = 0, h = 0;

    for (int i = 0; i < 64; i++) {
        if ((x >> i) & 1) {
            l ^= y << i;
            if (i)
                h ^= y >> (64 - i);
        }
    }
    *lo = l;
    *hi = h;
}

static void pclmul_control(void)
{
    const uint64_t x = 0x0123456789abcdefULL;
    const uint64_t y = 0xfedcba9876543210ULL;
    uint64_t slo, shi, ilo, ihi;
    uint64_t got[2];

    software_clmul(x, y, &slo, &shi);
    __m128i vx = _mm_set_epi64x(0, (long long)x);
    __m128i vy = _mm_set_epi64x(0, (long long)y);
    __m128i p = _mm_clmulepi64_si128(vx, vy, 0x00);
    _mm_storeu_si128((__m128i *)got, p);
    ilo = got[0];
    ihi = got[1];

    printf("pclmul_control_out=%016llx%016llx\n",
           (unsigned long long)ihi, (unsigned long long)ilo);
    printf("pclmul_control_ref=%016llx%016llx\n",
           (unsigned long long)shi, (unsigned long long)slo);
    if (ilo != slo || ihi != shi) {
        printf("pclmul_control=FAIL\n");
        fails++;
    } else {
        printf("pclmul_control=PASS (software carry-less multiply)\n");
    }
}

#if defined(__VAES__) && defined(__VPCLMULQDQ__) && defined(__AVX2__)
static void vaes_control(void)
{
    __m256i a = _mm256_set_epi64x(0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL,
                                  0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL);
    __m256i k = _mm256_set1_epi32(0x01020304);
    __m256i w = _mm256_aesenc_epi128(a, k);
    __m128i lo = _mm256_castsi256_si128(w);
    __m128i hi = _mm256_extracti128_si256(w, 1);
    __m128i elo = _mm_aesenc_si128(_mm256_castsi256_si128(a),
                                   _mm256_castsi256_si128(k));
    __m128i ehi = _mm_aesenc_si128(_mm256_extracti128_si256(a, 1),
                                   _mm256_extracti128_si256(k, 1));

    if (memcmp(&lo, &elo, 16) != 0 || memcmp(&hi, &ehi, 16) != 0) {
        printf("vaes_control=FAIL\n");
        fails++;
    } else {
        printf("vaes_control=PASS (256-bit VAES equals two 128-bit aesenc)\n");
    }
}

static void vpclmul_control(void)
{
    __m256i a = _mm256_set_epi64x(0, 0x1111111111111111ULL,
                                  0, 0x2222222222222222ULL);
    __m256i b = _mm256_set_epi64x(0, 0x3333333333333333ULL,
                                  0, 0x4444444444444444ULL);
    __m256i w = _mm256_clmulepi64_epi128(a, b, 0x00);
    uint64_t got[4];
    _mm256_storeu_si256((__m256i *)got, w);

    uint64_t lo0, hi0, lo1, hi1;
    software_clmul(0x2222222222222222ULL, 0x4444444444444444ULL, &lo0, &hi0);
    software_clmul(0x1111111111111111ULL, 0x3333333333333333ULL, &lo1, &hi1);
    if (got[0] != lo0 || got[1] != hi0 || got[2] != lo1 || got[3] != hi1) {
        printf("vpclmul_control=FAIL\n");
        fails++;
    } else {
        printf("vpclmul_control=PASS (256-bit VPCLMUL equals two lanes)\n");
    }
}
#endif

int main(void)
{
    unsigned a, b, c, d, a7, b7, c7, d7;
    uint64_t x;

    cpuid1(&a, &b, &c, &d);
    cpuid7(&a7, &b7, &c7, &d7);

    int sse2 = (d >> 26) & 1;
    int ssse3 = (c >> 9) & 1;
    int pclmul = (c >> 1) & 1;
    int aes = (c >> 25) & 1;
    int osxsave = (c >> 27) & 1;
    int avx = (c >> 28) & 1;
    int avx2 = (b7 >> 5) & 1;
    int avx512f = (b7 >> 16) & 1;
    int avx512vl = (b7 >> 31) & 1;
    int vaes = (c7 >> 9) & 1;
    int vpclmul = (c7 >> 10) & 1;

    x = osxsave ? xcr0() : 0;
    int os_avx = (x & 0x6) == 0x6;
    int os_avx512 = (x & 0xe6) == 0xe6;

    printf("CPUID leaf1.ECX known bits: sse2=%d ssse3=%d pclmulqdq=%d aes=%d "
           "osxsave=%d avx=%d\n",
           sse2, ssse3, pclmul, aes, osxsave, avx);
    printf("CPUID leaf7.0: avx2=%d avx512f=%d avx512vl=%d vaes=%d "
           "vpclmulqdq=%d\n",
           avx2, avx512f, avx512vl, vaes, vpclmul);
    printf("XCR0=0x%llx os_avx=%d os_avx512=%d\n",
           (unsigned long long)x, os_avx, os_avx512);
    printf("effective: aes=%d pclmulqdq=%d vaes256=%d vpclmul256=%d "
           "avx512=%d\n",
           aes, pclmul, vaes && os_avx, vpclmul && os_avx,
           avx512f && avx512vl && os_avx512);

    if (!(aes && pclmul)) {
        printf("poscontrol=NOT_APPLICABLE (required bits absent)\n");
        return 2;
    }

    aes_control();
    pclmul_control();

#if defined(__VAES__) && defined(__VPCLMULQDQ__) && defined(__AVX2__)
    if (vaes && os_avx && avx2)
        vaes_control();
    if (vpclmul && os_avx && avx2)
        vpclmul_control();
#else
    printf("vaes_control=NOT_COMPILED\n");
    printf("vpclmul_control=NOT_COMPILED\n");
#endif

    printf("poscontrol=%s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
