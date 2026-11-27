/*
 * pfp7_ilp.c — PFP-7 ILP bound probe.
 *
 * Two questions, both measured on this machine, no PMU needed:
 *
 *   calib : the effective core clock, from a long dependent `add` chain
 *           (1 cycle per add), and the sustained integer issue width, from k
 *           independent add chains.  Both are wall-clock measurements of
 *           instruction streams with a known cycle cost, so they do not
 *           depend on a frequency model.
 *   cios  : a transcription of this crate's CIOS Montgomery kernel at n = 16
 *           limbs (the 1024-bit CRT half), run three ways over identical
 *           operand sets:
 *             1-then-1 : two mont muls back to back (sequential)
 *             fused    : the same two mont muls advanced in one loop, limb of
 *                        A then limb of B, so the two carry chains are
 *                        independent and visible to the out-of-order engine
 *           The ratio fused/1-then-1 is the measured ILP available from
 *           interleaving.  It is a transcription, not the crate DSO: the
 *           crate's own instruction count per mont mul is taken from
 *           callgrind at the same digest and compared with this probe's, so
 *           the transcription is shown to be representative rather than
 *           assumed to be.
 *
 * The kernel shape follows src/bn/arith.rs::mont_mul_cios_into:
 *   for each limb of b:  acc += a*b[i];  acc += u*m;  (u = acc[0]*n0)
 * with a single masked conditional subtraction at the end.  The probe omits
 * the mask select from the timed loop's per-iteration cost only in that it
 * performs it once per mont mul, exactly as the source does.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define N 16

typedef unsigned __int128 u128;
typedef uint64_t u64;

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* ---- calibration ------------------------------------------------------- */

__attribute__((noinline)) static u64 calib_chain(u64 x, u64 iters)
{
    for (u64 i = 0; i < iters; i++) {
        x += 1;             /* one dependent add per iteration */
        /* Keep the add live: without this barrier LLVM recognises
         * `x += 1` in a loop and folds it to `x += iters`. */
        __asm__ volatile("" : "+r"(x));
    }
    return x;
}

__attribute__((noinline)) static u64 calib_width(u64 x, u64 iters)
{
    u64 a = x, b = x + 1, c = x + 2, d = x + 3, e = x + 4, f = x + 5;
    for (u64 i = 0; i < iters; i++) {
        a += 1; b += 1; c += 1; d += 1; e += 1; f += 1;
        /* Without a per-iteration barrier LLVM folds the six increments into
         * `x += iters`; the counter is otherwise a no-op register rotation. */
        __asm__ volatile("" : "+r"(a), "+r"(b), "+r"(c), "+r"(d), "+r"(e), "+r"(f));
    }
    __asm__ volatile("" : "+r"(a), "+r"(b), "+r"(c), "+r"(d), "+r"(e), "+r"(f));
    return a ^ b ^ c ^ d ^ e ^ f;
}

/* ---- CIOS Montgomery kernel, n = 16 ------------------------------------ */

struct mont {
    u64 a[N];
    u64 b[N];
    u64 m[N];
    u64 n0;
    u64 acc[N + 2];
    u64 diff[N];
    u64 out[N];
};

static void cios_init(struct mont *s, u64 seed)
{
    /* Operands: a, b < m, m odd and with the top bit set.  Values only have to
     * be representative; the kernel is constant-time in limb operations. */
    for (int j = 0; j < N; j++) {
        s->m[j] = 0x9e3779b97f4a7c15ull ^ (seed + (u64)j * 0x1234567ull);
        s->a[j] = 0x243f6a8885a308d3ull ^ (seed * 7 + (u64)j);
        s->b[j] = 0x13198a2e03707344ull ^ (seed * 13 + (u64)j);
    }
    s->m[0] |= 1;      /* odd modulus */
    s->m[N - 1] |= 1ull << 63;  /* full width */
    s->n0 = 1;         /* REDC word: value irrelevant to the instruction mix */
}

/* One CIOS Montgomery multiplication over the n = 16 limbs, following the
 * crate source's structure.  `acc` is the working accumulator (n + 2 limbs). */
static inline void cios_mul(struct mont *s)
{
    u64 *acc = s->acc;
    const u64 *a = s->a, *b = s->b, *m = s->m;
    memset(acc, 0, sizeof(u64) * (N + 2));
    for (int i = 0; i < N; i++) {
        u64 bi = b[i];
        u64 carry = 0;
        for (int j = 0; j < N; j++) {
            u128 v = (u128)a[j] * bi + acc[j] + carry;
            acc[j] = (u64)v;
            carry = (u64)(v >> 64);
        }
        u64 hi = acc[N] + carry;
        acc[N] = hi;
        acc[N + 1] = (hi < carry);

        u64 u = acc[0] * s->n0;
        u128 v = (u128)u * m[0] + acc[0];
        carry = (u64)(v >> 64);
        for (int j = 1; j < N; j++) {
            u128 w = (u128)u * m[j] + acc[j] + carry;
            acc[j - 1] = (u64)w;
            carry = (u64)(w >> 64);
        }
        u64 lo = acc[N] + carry;
        acc[N - 1] = lo;
        acc[N] = acc[N + 1] + (lo < carry);
    }
    u64 high = acc[N];
    u64 borrow = 0;
    for (int j = 0; j < N; j++) {
        u64 d1 = acc[j] - m[j];
        u64 b1 = acc[j] < m[j];
        u64 d2 = d1 - borrow;
        u64 b2 = d1 < borrow;
        s->diff[j] = d2;
        borrow = b1 | b2;
    }
    u64 keep = high | (borrow ^ 1);
    u64 mask = 0 - keep;
    for (int j = 0; j < N; j++) {
        s->out[j] = (s->diff[j] & mask) | (acc[j] & ~mask);
    }
}

/* Two mont muls advanced in one loop: the A and B carry chains are fully
 * independent, and both are visible in the same out-of-order window. */
static inline void cios_mul_x2(struct mont *A, struct mont *B)
{
    u64 *accA = A->acc, *accB = B->acc;
    const u64 *aA = A->a, *bA = A->b, *mA = A->m;
    const u64 *aB = B->a, *bB = B->b, *mB = B->m;
    memset(accA, 0, sizeof(u64) * (N + 2));
    memset(accB, 0, sizeof(u64) * (N + 2));
    for (int i = 0; i < N; i++) {
        u64 biA = bA[i], biB = bB[i];
        u64 carryA = 0, carryB = 0;
        for (int j = 0; j < N; j++) {
            u128 vA = (u128)aA[j] * biA + accA[j] + carryA;
            u128 vB = (u128)aB[j] * biB + accB[j] + carryB;
            accA[j] = (u64)vA;
            carryA = (u64)(vA >> 64);
            accB[j] = (u64)vB;
            carryB = (u64)(vB >> 64);
        }
        u64 hiA = accA[N] + carryA, hiB = accB[N] + carryB;
        accA[N] = hiA;
        accA[N + 1] = (hiA < carryA);
        accB[N] = hiB;
        accB[N + 1] = (hiB < carryB);

        u64 uA = accA[0] * A->n0, uB = accB[0] * B->n0;
        u128 v0A = (u128)uA * mA[0] + accA[0];
        u128 v0B = (u128)uB * mB[0] + accB[0];
        carryA = (u64)(v0A >> 64);
        carryB = (u64)(v0B >> 64);
        for (int j = 1; j < N; j++) {
            u128 wA = (u128)uA * mA[j] + accA[j] + carryA;
            u128 wB = (u128)uB * mB[j] + accB[j] + carryB;
            accA[j - 1] = (u64)wA;
            carryA = (u64)(wA >> 64);
            accB[j - 1] = (u64)wB;
            carryB = (u64)(wB >> 64);
        }
        u64 loA = accA[N] + carryA, loB = accB[N] + carryB;
        accA[N - 1] = loA;
        accA[N] = accA[N + 1] + (loA < carryA);
        accB[N - 1] = loB;
        accB[N] = accB[N + 1] + (loB < carryB);
    }
    for (int side = 0; side < 2; side++) {
        struct mont *s = side == 0 ? A : B;
        u64 *acc = s->acc;
        const u64 *m = s->m;
        u64 high = acc[N];
        u64 borrow = 0;
        for (int j = 0; j < N; j++) {
            u64 d1 = acc[j] - m[j];
            u64 b1 = acc[j] < m[j];
            u64 d2 = d1 - borrow;
            u64 b2 = d1 < borrow;
            s->diff[j] = d2;
            borrow = b1 | b2;
        }
        u64 keep = high | (borrow ^ 1);
        u64 mask = 0 - keep;
        for (int j = 0; j < N; j++) {
            s->out[j] = (s->diff[j] & mask) | (acc[j] & ~mask);
        }
    }
}

static u64 checksum(const struct mont *s)
{
    u64 x = 0;
    for (int j = 0; j < N; j++) {
        x ^= s->out[j];
    }
    return x;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "all";
    const u64 reps = argc > 2 ? strtoull(argv[2], NULL, 0) : 200000;

    if (strcmp(mode, "calib") == 0 || strcmp(mode, "all") == 0) {
        /* dependent chain: `iters` adds, 1 cycle each, minimum latency. */
        u64 iters = 200000000ull;
        double best = 1e30;
        for (int r = 0; r < 5; r++) {
            double t0 = now_ns();
            volatile u64 x = calib_chain(1, iters);
            double t1 = now_ns();
            (void)x;
            if (t1 - t0 < best) best = t1 - t0;
        }
        printf("CALIB chain_add_ps=%.3f(1/cycle) eff_ghz=%.3f\n",
               best / (double)iters * 1e3, (double)iters / best);
        best = 1e30;
        for (int r = 0; r < 5; r++) {
            double t0 = now_ns();
            volatile u64 x = calib_width(1, iters);
            double t1 = now_ns();
            (void)x;
            if (t1 - t0 < best) best = t1 - t0;
        }
        printf("CALIB width6_ps_per_iter=%.3f (6 independent adds; ideal 1 cycle/iter)\n",
               best / (double)iters * 1e3);
    }

    if (strcmp(mode, "cios") == 0 || strcmp(mode, "all") == 0) {
        static struct mont A, B;
        cios_init(&A, 1);
        cios_init(&B, 2);
        u64 sink = 0;
        /* warm-up */
        for (int r = 0; r < 2000; r++) {
            cios_mul(&A);
            cios_mul(&B);
        }
        double best_seq = 1e30, best_fus = 1e30, best_one = 1e30;
        for (int r = 0; r < 7; r++) {
            double t0 = now_ns();
            for (u64 i = 0; i < reps; i++) {
                cios_mul(&A);
                cios_mul(&B);
            }
            double t1 = now_ns();
            if (t1 - t0 < best_seq) best_seq = t1 - t0;
            t0 = now_ns();
            for (u64 i = 0; i < reps; i++) {
                cios_mul_x2(&A, &B);
            }
            t1 = now_ns();
            if (t1 - t0 < best_fus) best_fus = t1 - t0;
            t0 = now_ns();
            for (u64 i = 0; i < reps; i++) {
                cios_mul(&A);
            }
            t1 = now_ns();
            if (t1 - t0 < best_one) best_one = t1 - t0;
            sink ^= checksum(&A) ^ checksum(&B);
        }
        double per_op_seq = best_seq / (double)(2 * reps);
        double per_op_fus = best_fus / (double)(2 * reps);
        double per_op_one = best_one / (double)reps;
        printf("CIOS n=%d reps=%llu\n", N, (unsigned long long)reps);
        printf("RESULT single_ns_per_mul=%.2f\n", per_op_one);
        printf("RESULT seq2_ns_per_mul=%.2f\n", per_op_seq);
        printf("RESULT fused2_ns_per_mul=%.2f\n", per_op_fus);
        printf("RESULT fused_over_seq=%.4f (1.0000 = no ILP gain)\n",
               per_op_fus / per_op_seq);
        /* Value equality of the fused kernel against the sequential one: the
         * same single Montgomery multiplication, performed by each shape from
         * identical operands, must produce identical output limbs. */
        {
            static struct mont P, Q, R;
            int same = 1;
            cios_init(&P, 7);
            memcpy(&Q, &P, sizeof P);
            cios_init(&R, 8);
            cios_mul(&P);
            cios_mul_x2(&Q, &R);
            for (int j = 0; j < N; j++) {
                if (P.out[j] != Q.out[j]) same = 0;
            }
            printf("CHECK fused_equals_sequential=%d seq_out=%016llx fused_out=%016llx\n",
                   same, (unsigned long long)checksum(&P), (unsigned long long)checksum(&Q));
        }
    }
    return 0;
}
