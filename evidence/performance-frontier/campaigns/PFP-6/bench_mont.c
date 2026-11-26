/*
 * PFP-6 schedule crossover harness.
 *
 * WHAT THIS MEASURES, AND WHAT IT DOES NOT
 * ----------------------------------------
 * This is a standalone C transcription of four Montgomery schedules and two
 * pure-product schedules. It measures the *schedules* on this compiler, CPU and
 * flags. It is not a measurement of the crate's kernels: those are
 * `mont_mul_sos_into`, `mont_mul_cios_into` and `mont_sqr_into` in
 * `src/bn/arith.rs`, differentially verified against each other by
 * `cargo test --lib -- pfp6`. The crate's default schedule is unchanged
 * (`LADDER_SCHEDULE = Sos`), so no API performance row is claimed here.
 *
 * Schedules implemented:
 *   sos    - separated operand scanning: schoolbook product, then REDC
 *   cios   - coarsely integrated operand scanning
 *   comba  - product scanning (Comba) product, then REDC
 *   sqr    - dedicated squaring: Comba product from symmetry, then REDC
 *
 * Pure products (the Karatsuba question):
 *   product_schoolbook
 *   product_karatsuba (base case schoolbook, KBASE_ limbs)
 * Karatsuba's carry loops branch on data. It is measured only as a product-cost
 * experiment and is not proposed for the secret path.
 *
 * Not implemented here, and therefore not compared: FIOS and
 * almost-Montgomery. The receipt records that omission rather than implying a
 * result.
 *
 * Correctness in this harness is cross-schedule equality against `sos` over the
 * edge/adversarial population below. The crate's own `sos` reference is checked
 * against `limbs::{mul, rem}` separately (bn::mont::etp4_verification).
 *
 * Build/run in the court:
 *   cc -O2 -g -o bench_mont bench_mont.c
 *   taskset -c 1 ./bench_mont
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef uint64_t u64;
typedef unsigned __int128 u128;

#define MAX_LIMBS 64 /* 4096 bits */
#define MAXPOP 16
#define REPS 15
#define KBASE_ 8

static volatile u64 sink;

/* ---------------------------------------------------------------- helpers */

static double now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static inline u128 mul_add(u64 a, u64 b, u64 c, u64 d)
{
    return (u128)a * b + c + d;
}

/* acc (192-bit) += v. The caller's column bound keeps acc below 2^192. */
static inline void add192(u64 acc[3], u128 v)
{
    u64 lo = (u64)v, hi = (u64)(v >> 64);
    u64 s0 = acc[0] + lo, c0 = (s0 < acc[0]);
    u64 s1 = acc[1] + hi, c1 = (s1 < acc[1]);
    u64 s1b = s1 + c0, c2 = (s1b < s1);

    acc[0] = s0;
    acc[1] = s1b;
    acc[2] += c1 + c2;
}

/* REDC on t[0..=2n]; canonical result (< m) into out. */
static void redc(u64 *t, const u64 *m, size_t n, u64 n0, u64 *out)
{
    u64 high, borrow, keep, mask;

    for (size_t i = 0; i < n; i++) {
        u64 u = t[i] * n0;
        u64 carry = 0;

        for (size_t j = 0; j < n; j++) {
            u128 v = mul_add(u, m[j], t[i + j], carry);
            t[i + j] = (u64)v;
            carry = (u64)(v >> 64);
        }
        u64 c = carry;
        for (size_t k = i + n; k <= 2 * n; k++) {
            u64 s = t[k] + c;
            c = (s < t[k]);
            t[k] = s;
        }
    }

    high = t[2 * n];
    borrow = 0;
    for (size_t j = 0; j < n; j++) {
        u64 d1 = t[n + j] - m[j];
        u64 b1 = (t[n + j] < m[j]);
        u64 d2 = d1 - borrow;
        u64 b2 = (d1 < borrow);
        out[j] = d2;
        borrow = b1 | b2;
    }
    keep = (high ^ 1) & borrow; /* 1 => the value was below m */
    mask = 0 - keep;
    for (size_t j = 0; j < n; j++) {
        u64 d = out[j];
        out[j] = (t[n + j] & mask) | (d & ~mask);
    }
}

/* ------------------------------------------------------------- schedules */

/* sos: schoolbook product into t[0..2n], then REDC. */
static void mont_sos(u64 *out, const u64 *a, const u64 *b, const u64 *m,
                     size_t n, u64 n0, u64 *t)
{
    memset(t, 0, (2 * n + 1) * sizeof(u64));
    for (size_t i = 0; i < n; i++) {
        u64 carry = 0;
        for (size_t j = 0; j < n; j++) {
            u128 v = mul_add(a[i], b[j], t[i + j], carry);
            t[i + j] = (u64)v;
            carry = (u64)(v >> 64);
        }
        t[i + n] = carry;
    }
    redc(t, m, n, n0, out);
}

/* cios: interleaved product and reduction, n+2 limb accumulator. */
static void mont_cios(u64 *out, const u64 *a, const u64 *b, const u64 *m,
                      size_t n, u64 n0, u64 *t)
{
    u64 borrow, keep, mask;

    memset(t, 0, (n + 2) * sizeof(u64));
    for (size_t i = 0; i < n; i++) {
        u64 bi = b[i];
        u64 carry = 0;

        for (size_t j = 0; j < n; j++) {
            u128 v = mul_add(a[j], bi, t[j], carry);
            t[j] = (u64)v;
            carry = (u64)(v >> 64);
        }
        {
            u64 s = t[n] + carry;
            u64 of = (s < t[n]);
            t[n] = s;
            t[n + 1] = of;
        }
        {
            u64 u = t[0] * n0;
            u128 v = mul_add(u, m[0], t[0], 0);
            carry = (u64)(v >> 64);
            for (size_t j = 1; j < n; j++) {
                v = mul_add(u, m[j], t[j], carry);
                t[j - 1] = (u64)v;
                carry = (u64)(v >> 64);
            }
        }
        {
            u64 s = t[n] + carry;
            u64 of = (s < t[n]);
            t[n - 1] = s;
            t[n] = t[n + 1] + of;
        }
    }

    borrow = 0;
    for (size_t j = 0; j < n; j++) {
        u64 d1 = t[j] - m[j];
        u64 b1 = (t[j] < m[j]);
        u64 d2 = d1 - borrow;
        u64 b2 = (d1 < borrow);
        out[j] = d2;
        borrow = b1 | b2;
    }
    keep = t[n] | (borrow ^ 1); /* 1 => subtract */
    mask = 0 - keep;
    for (size_t j = 0; j < n; j++) {
        u64 d = out[j];
        out[j] = (t[j] & ~mask) | (d & mask);
    }
}

/* comba: product-scanning product into t[0..2n], then REDC. */
static void mont_comba(u64 *out, const u64 *a, const u64 *b, const u64 *m,
                       size_t n, u64 n0, u64 *t)
{
    u64 acc[3] = {0, 0, 0};

    memset(t, 0, (2 * n + 1) * sizeof(u64));
    for (size_t k = 0; k < 2 * n; k++) {
        size_t lo = (k >= n - 1) ? k - (n - 1) : 0;
        size_t hi = (k < n) ? k : n - 1;

        for (size_t i = lo; i <= hi; i++) {
            size_t j = k - i;
            add192(acc, (u128)a[i] * b[j]);
        }
        t[k] = acc[0];
        acc[0] = acc[1];
        acc[1] = acc[2];
        acc[2] = 0;
    }
    redc(t, m, n, n0, out);
}

/* sqr: Comba product from a's symmetry, then REDC. */
static void mont_sqr(u64 *out, const u64 *a, const u64 *m, size_t n, u64 n0,
                     u64 *t)
{
    u64 acc[3] = {0, 0, 0};

    memset(t, 0, (2 * n + 1) * sizeof(u64));
    for (size_t k = 0; k < 2 * n; k++) {
        if ((k & 1) == 0) {
            size_t i = k / 2;
            if (i < n)
                add192(acc, (u128)a[i] * a[i]);
        }
        if (k >= 1) {
            size_t lo = (k >= n - 1) ? k - (n - 1) : 0;
            size_t hi = (k - 1) / 2;
            for (size_t i = lo; i <= hi; i++) {
                size_t j = k - i;
                u128 v = (u128)a[i] * a[j];
                add192(acc, v);
                add192(acc, v);
            }
        }
        t[k] = acc[0];
        acc[0] = acc[1];
        acc[1] = acc[2];
        acc[2] = 0;
    }
    redc(t, m, n, n0, out);
}

/* ------------------------------------------------------- pure products */

static void product_schoolbook(u64 *res, const u64 *a, const u64 *b,
                               size_t n)
{
    memset(res, 0, 2 * n * sizeof(u64));
    for (size_t i = 0; i < n; i++) {
        u64 carry = 0;
        for (size_t j = 0; j < n; j++) {
            u128 v = mul_add(a[i], b[j], res[i + j], carry);
            res[i + j] = (u64)v;
            carry = (u64)(v >> 64);
        }
        res[i + n] = carry;
    }
}

static void add_vec(u64 *out, const u64 *a, size_t an, const u64 *b,
                    size_t bn)
{
    size_t n = an > bn ? an : bn;
    u64 carry = 0;

    for (size_t i = 0; i < n; i++) {
        u64 x = i < an ? a[i] : 0;
        u64 y = i < bn ? b[i] : 0;
        u64 s = x + y;
        u64 c1 = (s < x);
        u64 s2 = s + carry;
        u64 c2 = (s2 < s);
        out[i] = s2;
        carry = c1 | c2;
    }
    out[n] = carry;
}

static void sub_from(u64 *dst, size_t dstlen, const u64 *src, size_t srclen)
{
    u64 borrow = 0;

    for (size_t i = 0; i < dstlen; i++) {
        u64 s = i < srclen ? src[i] : 0;
        u64 d1 = dst[i] - s;
        u64 b1 = (dst[i] < s);
        u64 d2 = d1 - borrow;
        u64 b2 = (d1 < borrow);
        dst[i] = d2;
        borrow = b1 | b2;
    }
}

static void add_into(u64 *dst, size_t dstlen, const u64 *src, size_t srclen,
                     size_t off)
{
    u64 carry = 0;
    size_t i;

    for (i = 0; i < srclen && off + i < dstlen; i++) {
        u64 s = dst[off + i] + src[i];
        u64 c1 = (s < dst[off + i]);
        u64 s2 = s + carry;
        u64 c2 = (s2 < s);
        dst[off + i] = s2;
        carry = c1 | c2;
    }
    for (; carry && off + i < dstlen; i++) {
        u64 s = dst[off + i] + carry;
        carry = (s < dst[off + i]);
        dst[off + i] = s;
    }
}

/* Recursive Karatsuba. Variable-time, and only for the product-cost experiment;
 * it is not a constant-time kernel. */
static void product_karatsuba(u64 *res, const u64 *a, const u64 *b, size_t n)
{
    size_t h, l;

    if (n <= KBASE_) {
        product_schoolbook(res, a, b, n);
        return;
    }
    h = n / 2;
    l = n - h;

    u64 a0[h], a1[l], b0[h], b1[l];
    u64 sa[l + 1], sb[l + 1];
    u64 z0[2 * h], z2[2 * l], z1[2 * l + 2];

    memcpy(a0, a, h * sizeof(u64));
    memcpy(a1, a + h, l * sizeof(u64));
    memcpy(b0, b, h * sizeof(u64));
    memcpy(b1, b + h, l * sizeof(u64));
    add_vec(sa, a0, h, a1, l);
    add_vec(sb, b0, h, b1, l);

    product_karatsuba(z0, a0, b0, h);
    product_karatsuba(z2, a1, b1, l);
    product_karatsuba(z1, sa, sb, l + 1);
    sub_from(z1, 2 * l + 2, z0, 2 * h);
    sub_from(z1, 2 * l + 2, z2, 2 * l);

    memset(res, 0, 2 * n * sizeof(u64));
    add_into(res, 2 * n, z0, 2 * h, 0);
    add_into(res, 2 * n, z1, 2 * l + 2, h);
    add_into(res, 2 * n, z2, 2 * l, 2 * h);
}

/* --------------------------------------------------------------- setup */

static u64 rng_state = 0x5046503650485036ULL;

static u64 xorshift64(void)
{
    u64 x = rng_state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

/* An odd modulus with the top bit of the top limb set (full n-limb width). */
static void make_modulus(u64 *m, size_t n)
{
    for (size_t i = 0; i < n; i++)
        m[i] = xorshift64();
    m[0] |= 1;
    m[n - 1] |= 0x8000000000000000ULL;
}

/* -m^-1 mod 2^64, Newton's iteration. */
static u64 inverse_word(u64 m0)
{
    u64 inv = m0;

    for (int i = 0; i < 6; i++)
        inv *= 2 - m0 * inv;
    return 0 - inv;
}

static int cmp_vec(const u64 *a, const u64 *b, size_t n)
{
    for (size_t i = n; i-- > 0;) {
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

static void sub_one(u64 *out, const u64 *a, size_t n)
{
    u64 borrow = 1;

    for (size_t i = 0; i < n; i++) {
        u64 d = a[i] - borrow;
        borrow = (a[i] < borrow);
        out[i] = d;
    }
}

/* A population of operands below m: 0, 1, 2, m-1, m-2, m/2, a one-limb value,
 * a top-limb-only value, and pseudo-random values whose top limb is strictly
 * below m's top limb (hence < m). */
static size_t make_population(u64 *vals, size_t n, const u64 *m)
{
    size_t count = 0;

    memset(vals, 0, MAXPOP * n * sizeof(u64));
    count = 0; /* 0 */
    count++;
    vals[count * n] = 1;
    count++;
    vals[count * n] = 2;
    count++;
    sub_one(vals + count * n, m, n); /* m - 1 */
    count++;
    {
        u64 t[MAX_LIMBS];
        sub_one(t, m, n);
        sub_one(vals + count * n, t, n); /* m - 2 */
        count++;
    }
    {
        u64 carry = 0; /* m / 2 by a right shift */
        for (size_t i = n; i-- > 0;) {
            u64 v = m[i];
            vals[count * n + i] = (v >> 1) | (carry << 63);
            carry = v & 1;
        }
        count++;
    }
    vals[count * n] = ~0ULL; /* one limb only */
    count++;
    vals[count * n + n - 1] = 1; /* top limb only */
    count++;
    for (int r = 0; r < 6; r++) {
        u64 *v = vals + count * n;
        for (size_t i = 0; i < n; i++)
            v[i] = xorshift64();
        v[n - 1] &= m[n - 1] >> 1; /* strictly below m */
        count++;
    }
    return count;
}

/* ----------------------------------------------------------- comparison */

static int differential(size_t n, const u64 *m, u64 n0, int bits)
{
    static u64 vals[MAXPOP * MAX_LIMBS];
    u64 ref[MAX_LIMBS], got[MAX_LIMBS], t[2 * MAX_LIMBS + 1];
    size_t pop = make_population(vals, n, m);
    size_t pairs = 0, sqrs = 0;
    int cios_mm = 0, comba_mm = 0, sqr_mm = 0;

    for (size_t ai = 0; ai < pop; ai++) {
        for (size_t bi = 0; bi < pop; bi++) {
            const u64 *a = vals + ai * n;
            const u64 *b = vals + bi * n;

            mont_sos(ref, a, b, m, n, n0, t);
            mont_cios(got, a, b, m, n, n0, t);
            if (cmp_vec(ref, got, n) != 0)
                cios_mm++;
            mont_comba(got, a, b, m, n, n0, t);
            if (cmp_vec(ref, got, n) != 0)
                comba_mm++;
            pairs++;
        }
        {
            const u64 *a = vals + ai * n;

            mont_sos(ref, a, a, m, n, n0, t);
            mont_sqr(got, a, m, n, n0, t);
            if (cmp_vec(ref, got, n) != 0)
                sqr_mm++;
            sqrs++;
        }
    }
    printf("DIFFERENTIAL cios bits=%d cases=%zu mismatches=%d\n", bits, pairs,
           cios_mm);
    printf("DIFFERENTIAL comba bits=%d cases=%zu mismatches=%d\n", bits, pairs,
           comba_mm);
    printf("DIFFERENTIAL sqr bits=%d cases=%zu mismatches=%d\n", bits, sqrs,
           sqr_mm);
    return cios_mm + comba_mm + sqr_mm;
}

/* -------------------------------------------------------------- timing */

static const int BIT_SIZES[] = {256, 384, 512, 1024, 2048, 4096};
#define NSIZES (sizeof(BIT_SIZES) / sizeof(BIT_SIZES[0]))

typedef void (*mul_fn)(u64 *, const u64 *, const u64 *, const u64 *, size_t,
                       u64, u64 *);

static int cmp_double(const void *x, const void *y)
{
    double a = *(const double *)x, b = *(const double *)y;

    return (a > b) - (a < b);
}

static double median(double *v, int n)
{
    qsort(v, n, sizeof(double), cmp_double);
    return (n & 1) ? v[n / 2] : 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

static long iterations_for(size_t n)
{
    /* Roughly 2-10 ms per repetition; scales with the n^2 work. */
    long base = (long)(4000000.0 / ((double)n * (double)n)) + 1;

    if (base < 100)
        base = 100;
    if (base > 400000)
        base = 400000;
    return base;
}

static void emit(const char *name, size_t n, const double *samples, long iters)
{
    double tmp[REPS];
    double med, min;

    memcpy(tmp, samples, REPS * sizeof(double));
    med = median(tmp, REPS); /* sorts the copy */
    min = tmp[0];
    for (int r = 0; r < REPS; r++)
        printf("SAMPLE %s limbs=%zu bits=%zu rep=%d ns=%.4f\n", name, n,
               n * 64, r, samples[r]);
    printf("SUMMARY %s limbs=%zu bits=%zu median_ns=%.4f min_ns=%.4f iters=%ld\n",
           name, n, n * 64, med, min, iters);
}

static double time_mul(mul_fn fn, size_t n, const u64 *a, const u64 *b,
                       const u64 *m, u64 n0, long iters)
{
    u64 out[MAX_LIMBS], t[2 * MAX_LIMBS + 1];
    double t0 = now_ns();

    for (long i = 0; i < iters; i++) {
        fn(out, a, b, m, n, n0, t);
        sink ^= out[0];
    }
    return (now_ns() - t0) / (double)iters;
}

static double time_sqr(size_t n, const u64 *a, const u64 *m, u64 n0,
                       long iters)
{
    u64 out[MAX_LIMBS], t[2 * MAX_LIMBS + 1];
    double t0 = now_ns();

    for (long i = 0; i < iters; i++) {
        mont_sqr(out, a, m, n, n0, t);
        sink ^= out[0];
    }
    return (now_ns() - t0) / (double)iters;
}

static double time_product(int karatsuba, size_t n, const u64 *a,
                           const u64 *b, long iters)
{
    u64 res[2 * MAX_LIMBS];
    double t0 = now_ns();

    for (long i = 0; i < iters; i++) {
        if (karatsuba)
            product_karatsuba(res, a, b, n);
        else
            product_schoolbook(res, a, b, n);
        sink ^= res[0];
    }
    return (now_ns() - t0) / (double)iters;
}

static int product_differential(size_t n, const u64 *a, const u64 *b)
{
    u64 ref[2 * MAX_LIMBS], got[2 * MAX_LIMBS];

    product_schoolbook(ref, a, b, n);
    product_karatsuba(got, a, b, n);
    return cmp_vec(ref, got, 2 * n) == 0 ? 0 : 1;
}

int main(void)
{
    static u64 a[MAX_LIMBS], b[MAX_LIMBS], m[MAX_LIMBS], ra[MAX_LIMBS],
        rb[MAX_LIMBS];

    printf("PFP-6 bench_mont: schedules=sos,cios,comba,sqr products=schoolbook,karatsuba\n");
    printf("REPS=%d KBASE=%d INTERLEAVED=1\n", REPS, KBASE_);

    for (size_t s = 0; s < NSIZES; s++) {
        int bits = BIT_SIZES[s];
        size_t n = (size_t)bits / 64;
        int mismatches, pd_mm = 0;
        u64 n0;
        long iters, piters;
        double sos[REPS], cios[REPS], comba[REPS], sqr[REPS], mulsq[REPS];
        double sch[REPS], kar[REPS];

        make_modulus(m, n);
        n0 = inverse_word(m[0]);
        sub_one(a, m, n); /* a = m - 1 */
        sub_one(b, a, n); /* b = m - 2 */
        mismatches = differential(n, m, n0, bits);
        if (mismatches != 0)
            printf("DIFFERENTIAL_FAIL bits=%d mismatches=%d\n", bits,
                   mismatches);
        pd_mm += product_differential(n, a, b);
        for (int r = 0; r < 3; r++) {
            for (size_t i = 0; i < n; i++) {
                ra[i] = xorshift64();
                rb[i] = xorshift64();
            }
            pd_mm += product_differential(n, ra, rb);
        }
        printf("DIFFERENTIAL product bits=%d cases=4 mismatches=%d\n", bits,
               pd_mm);

        iters = iterations_for(n);
        piters = iters * 2;
        for (long i = 0; i < iters / 4 + 1; i++) {
            (void)time_mul(mont_sos, n, a, b, m, n0, 1);
            (void)time_mul(mont_cios, n, a, b, m, n0, 1);
            (void)time_mul(mont_comba, n, a, b, m, n0, 1);
            (void)time_sqr(n, a, m, n0, 1);
            (void)time_mul(mont_sos, n, a, a, m, n0, 1);
            (void)time_product(0, n, a, b, 1);
            (void)time_product(1, n, a, b, 1);
        }
        /* Interleave every schedule within each repetition, so the ratio is
         * paired and a slow drift hits all arms the same way. */
        for (int r = 0; r < REPS; r++) {
            sos[r] = time_mul(mont_sos, n, a, b, m, n0, iters);
            cios[r] = time_mul(mont_cios, n, a, b, m, n0, iters);
            comba[r] = time_mul(mont_comba, n, a, b, m, n0, iters);
            sqr[r] = time_sqr(n, a, m, n0, iters);
            mulsq[r] = time_mul(mont_sos, n, a, a, m, n0, iters);
            sch[r] = time_product(0, n, a, b, piters);
            kar[r] = time_product(1, n, a, b, piters);
        }
        emit("mont_sos", n, sos, iters);
        emit("mont_cios", n, cios, iters);
        emit("mont_comba", n, comba, iters);
        emit("mont_sqr", n, sqr, iters);
        emit("mont_mul_for_sqr", n, mulsq, iters);
        emit("product_schoolbook", n, sch, piters);
        emit("product_karatsuba", n, kar, piters);
    }

    printf("SINK %llu\n", (unsigned long long)sink);
    return 0;
}
