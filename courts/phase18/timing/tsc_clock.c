/*
 * tsc_clock.c — T17 substitute for a hardware PMU: serialised RDTSC timing.
 *
 * This host/guest exposes no PMU (`CPUID.0AH` returns 0; there is no `cpu`
 * event source), so `perf stat -e cpu-cycles` cannot exist here.  RDTSC is
 * still available.  This harness:
 *
 *   1. calibrates the invariant TSC against CLOCK_MONOTONIC,
 *   2. measures the overhead/resolution of one serialised read pair,
 *   3. times a deterministic dependent-integer loop (a known workload), and
 *   4. times the crate's own BN_mod_exp_mont_consttime at 2048 bits and the
 *      RSA-2048 CRT shape, so the substitute is exercised on the measured
 *      operation rather than only on synthetic arithmetic.
 *
 * RDTSC IS NOT A PMU COUNTER.  It counts reference-clock ticks at the nominal
 * TSC frequency (or a hypervisor's emulation of it), not retired core cycles,
 * instructions, cache misses or any other architectural event.  It cannot
 * attribute cost to a source, cannot count events, and its ticks do not track
 * core-frequency changes.  The serialising fences bound reordering across the
 * measured region; they do not remove measurement perturbation from interrupts
 * or from out-of-order execution inside the region.  See the README and
 * court/tmp/t1718/NOTES.md for the stated limits.
 *
 * Build and run through run_pmu_substitutes.sh (inside the court).
 */
#define _GNU_SOURCE
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(__x86_64__) && !defined(__i386__)
#error "tsc_clock.c requires x86 RDTSC/RDTSCP"
#endif

/* The resolution probe takes 1000 samples; every array bound must cover it. */
#define MAX_SAMPLES 1024

static double now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* lfence; rdtsc serialises prior instructions before the counter is read. */
static inline uint64_t tsc_begin(void)
{
    uint32_t lo, hi;

    __asm__ __volatile__("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

/* rdtscp waits for prior instructions; the trailing lfence orders later ones. */
static inline uint64_t tsc_end(void)
{
    uint32_t lo, hi, aux;

    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
    __asm__ __volatile__("lfence" ::: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

    return (x > y) - (x < y);
}

static uint64_t median_u64(uint64_t *v, int n)
{
    qsort(v, n, sizeof(*v), cmp_u64);
    return v[n / 2];
}

/* Deterministic dependent work; the compiler barrier keeps every iteration. */
__attribute__((noinline))
static uint64_t xorshift_work(uint64_t iterations)
{
    uint64_t x = UINT64_C(0x9e3779b97f4a7c15);
    uint64_t i;

    for (i = 0; i < iterations; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        __asm__ __volatile__("" : "+r"(x));
    }
    return x;
}

static int make_operands(int bits, BIGNUM **m, BIGNUM **e)
{
    *m = BN_new();
    *e = BN_new();
    if (*m == NULL || *e == NULL)
        return 0;
    return BN_rand(*m, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD) &&
           BN_rand(*e, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
}

static void report_cycles(const char *name, uint64_t *samples, int n,
                          double ns_per_tick)
{
    uint64_t copy[MAX_SAMPLES];
    uint64_t med, min = samples[0], max = samples[0];
    double sum = 0.0;
    int i;

    for (i = 0; i < n; i++) {
        copy[i] = samples[i];
        sum += (double)samples[i];
        if (samples[i] < min)
            min = samples[i];
        if (samples[i] > max)
            max = samples[i];
    }
    med = median_u64(copy, n);
    printf("TSC %s n=%d median_cycles=%llu min=%llu max=%llu mean=%.1f "
           "median_ns=%.1f\n",
           name, n, (unsigned long long)med, (unsigned long long)min,
           (unsigned long long)max, sum / (double)n,
           (double)med * ns_per_tick);
}

static int bench_modexp(int bits, int iterations, double ns_per_tick)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = NULL, *e = NULL, *base = BN_new(), *r = BN_new();
    uint64_t samples[MAX_SAMPLES];
    char name[64];
    int i, ok = 0;

    if (ctx == NULL || base == NULL || r == NULL || iterations > MAX_SAMPLES)
        goto out;
    if (!make_operands(bits, &m, &e) || !BN_set_word(base, 3))
        goto out;
    if (!BN_mod_exp_mont_consttime(r, base, e, m, ctx, NULL))
        goto out;

    for (i = 0; i < iterations; i++) {
        uint64_t t0 = tsc_begin();
        int rc = BN_mod_exp_mont_consttime(r, base, e, m, ctx, NULL);
        uint64_t t1 = tsc_end();

        if (!rc)
            goto out;
        samples[i] = t1 - t0;
    }
    snprintf(name, sizeof(name), "workload=bn_modexp bits=%d", bits);
    report_cycles(name, samples, iterations, ns_per_tick);
    ok = 1;

out:
    BN_free(m);
    BN_free(e);
    BN_free(base);
    BN_free(r);
    BN_CTX_free(ctx);
    return ok;
}

static int bench_rsa_crt(int iterations, double ns_per_tick)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = NULL, *q = NULL, *dp = NULL, *dq = NULL;
    BIGNUM *base = BN_new(), *r1 = BN_new(), *r2 = BN_new();
    uint64_t samples[MAX_SAMPLES];
    int i, ok = 0;

    if (ctx == NULL || base == NULL || r1 == NULL || r2 == NULL ||
        iterations > MAX_SAMPLES)
        goto out;
    if (!make_operands(1024, &p, &dp) || !make_operands(1024, &q, &dq))
        goto out;
    if (!BN_set_word(base, 3))
        goto out;
    if (!BN_mod_exp_mont_consttime_x2(r1, base, dp, p, NULL, r2, base, dq, q,
                                      NULL, ctx))
        goto out;

    for (i = 0; i < iterations; i++) {
        uint64_t t0 = tsc_begin();
        int rc = BN_mod_exp_mont_consttime_x2(r1, base, dp, p, NULL, r2, base,
                                              dq, q, NULL, ctx);
        uint64_t t1 = tsc_end();

        if (!rc)
            goto out;
        samples[i] = t1 - t0;
    }
    report_cycles("workload=rsa2048_crt", samples, iterations, ns_per_tick);
    ok = 1;

out:
    BN_free(p);
    BN_free(q);
    BN_free(dp);
    BN_free(dq);
    BN_free(base);
    BN_free(r1);
    BN_free(r2);
    BN_CTX_free(ctx);
    return ok;
}

int main(void)
{
    const uint64_t work_iters = UINT64_C(20000000);
    uint64_t t0, t1, samples[MAX_SAMPLES];
    double w0, w1, freq_hz, ns_per_tick;
    int i;

    /* Calibrate: the TSC is invariant, so it keeps ticking across a busy wait. */
    w0 = now_ns();
    t0 = tsc_begin();
    while (now_ns() - w0 < 2.0e8)
        ;
    t1 = tsc_end();
    w1 = now_ns();
    freq_hz = (double)(t1 - t0) / ((w1 - w0) / 1e9);
    ns_per_tick = 1e9 / freq_hz;
    printf("TSC calibration ticks=%llu wall_ns=%.0f freq_hz=%.0f mhz=%.3f "
           "ns_per_tick=%.6f\n",
           (unsigned long long)(t1 - t0), w1 - w0, freq_hz, freq_hz / 1e6,
           ns_per_tick);

    /* Resolution: the cost of one serialised read pair, read on the same core. */
    for (i = 0; i < 1000; i++) {
        uint64_t a = tsc_begin();
        uint64_t b = tsc_end();

        samples[i] = b - a;
    }
    report_cycles("instrument=empty_read_pair", samples, 1000, ns_per_tick);

    for (i = 0; i < 7; i++) {
        uint64_t a = tsc_begin();
        uint64_t sink = xorshift_work(work_iters);
        uint64_t b = tsc_end();

        samples[i] = b - a;
        if (sink == 0)
            fprintf(stderr, "xorshift sink was zero\n");
    }
    {
        uint64_t med = median_u64(samples, 7);
        printf("TSC workload=xorshift64 iters=%llu median_total_cycles=%llu "
               "cycles_per_iter=%.2f median_total_ns=%.1f\n",
               (unsigned long long)work_iters, (unsigned long long)med,
               (double)med / (double)work_iters,
               (double)med * ns_per_tick);
    }

    if (!bench_modexp(2048, 50, ns_per_tick))
        return 1;
    if (!bench_rsa_crt(50, ns_per_tick))
        return 1;
    return 0;
}
