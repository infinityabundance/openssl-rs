/*
 * dudect harness: BN_mod_exp_mont_consttime, BN_mod_inverse, and two controls.
 *
 * Same operands as the Phase-18 probe:
 *   p = 2^255-19, a = 5,
 *   class 0 e0 = 2^254+1 (Hamming weight 2), class 1 e1 = 2^255-1 (weight 255)
 *   inverse class 0 a0 = 2^200+1, class 1 a1 = 2^254-3.
 *
 * Controls:
 *   cmpcmp    CRYPTO_memcmp over 2 x 4 KiB, mismatch at first vs last byte
 *             (constant-time reference; negative control)
 *   cmpnaive  deliberately early-exiting comparison over the same buffers
 *             (leaky positive control)
 *
 * Built against dudect commit dc269651fb2567e46755cfb2a13d3875592968b5.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

enum mode { M_MODEXP, M_INVERSE, M_CMPCMP, M_CMPNAIVE };
static enum mode g_mode;

static BN_CTX *g_ctx;
static BIGNUM *g_r, *g_a, *g_p, *g_e0, *g_e1, *g_a0, *g_a1;
static unsigned char *g_a_buf, *g_first, *g_last;

#define CTL_REPS 32
#define CTL_LEN 4096

static int setup_bn(void)
{
    g_ctx = BN_CTX_new();
    g_r = BN_new(); g_a = BN_new(); g_p = BN_new();
    g_e0 = BN_new(); g_e1 = BN_new(); g_a0 = BN_new(); g_a1 = BN_new();
    if (!g_ctx || !g_r || !g_a || !g_p || !g_e0 || !g_e1 || !g_a0 || !g_a1)
        return 0;
    if (!BN_one(g_p) || !BN_lshift(g_p, g_p, 255) || !BN_sub_word(g_p, 19))
        return 0;
    if (!BN_set_word(g_a, 5))
        return 0;
    if (!BN_one(g_e0) || !BN_lshift(g_e0, g_e0, 254) || !BN_add_word(g_e0, 1))
        return 0;
    if (!BN_one(g_e1) || !BN_lshift(g_e1, g_e1, 255) || !BN_sub_word(g_e1, 1))
        return 0;
    if (!BN_one(g_a0) || !BN_lshift(g_a0, g_a0, 200) || !BN_add_word(g_a0, 1))
        return 0;
    if (!BN_one(g_a1) || !BN_lshift(g_a1, g_a1, 254) || !BN_sub_word(g_a1, 3))
        return 0;
    return 1;
}

static int setup_ctl(void)
{
    if (posix_memalign((void **)&g_a_buf, 64, CTL_LEN) != 0 ||
        posix_memalign((void **)&g_first, 64, CTL_LEN) != 0 ||
        posix_memalign((void **)&g_last, 64, CTL_LEN) != 0)
        return 0;
    memset(g_a_buf, 0x5a, CTL_LEN);
    memset(g_first, 0x5a, CTL_LEN);
    memset(g_last, 0x5a, CTL_LEN);
    g_first[0] ^= 1;
    g_last[CTL_LEN - 1] ^= 1;
    return 1;
}

__attribute__((noinline))
static int naive_cmp(const unsigned char *a, const unsigned char *b, size_t n)
{
    volatile unsigned char acc = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            acc = (unsigned char)(acc + 1);
            break;
        }
        acc = (unsigned char)(acc * 3u + b[i]);
    }
    return acc;
}

uint8_t do_one_computation(uint8_t *data)
{
    int cls = data[0] & 1;
    int i, r = 0;

    switch (g_mode) {
    case M_MODEXP:
        BN_mod_exp_mont_consttime(g_r, g_a, cls ? g_e1 : g_e0, g_p, g_ctx, NULL);
        return 0;
    case M_INVERSE:
        BN_mod_inverse(g_r, cls ? g_a1 : g_a0, g_p, g_ctx);
        return 0;
    case M_CMPCMP:
        for (i = 0; i < CTL_REPS; i++)
            r |= CRYPTO_memcmp(g_a_buf, cls ? g_last : g_first, CTL_LEN);
        return (uint8_t)r;
    case M_CMPNAIVE:
        for (i = 0; i < CTL_REPS; i++)
            r |= naive_cmp(g_a_buf, cls ? g_last : g_first, CTL_LEN);
        return (uint8_t)r;
    }
    return 0;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes)
{
    size_t i;

    for (i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        input_data[i * c->chunk_size] = classes[i];
    }
}

int main(int argc, char **argv)
{
    dudect_config_t config = { .chunk_size = 1, .number_measurements = 20000 };
    dudect_ctx_t ctx;
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    const char *m = argc > 1 ? argv[1] : "";
    int batches = 0;

    if (strcmp(m, "modexp") == 0) g_mode = M_MODEXP;
    else if (strcmp(m, "inverse") == 0) g_mode = M_INVERSE;
    else if (strcmp(m, "cmpcmp") == 0) g_mode = M_CMPCMP;
    else if (strcmp(m, "cmpnaive") == 0) g_mode = M_CMPNAIVE;
    else { fprintf(stderr, "usage: %s modexp|inverse|cmpcmp|cmpnaive\n", argv[0]); return 2; }

    if (g_mode == M_MODEXP || g_mode == M_INVERSE) {
        if (!setup_bn()) { fprintf(stderr, "setup_bn failed\n"); return 2; }
    } else {
        if (!setup_ctl()) { fprintf(stderr, "setup_ctl failed\n"); return 2; }
    }
    if (argc > 2)
        config.number_measurements = (size_t)strtoul(argv[2], NULL, 10);

    dudect_init(&ctx, &config);
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET && batches < 3) {
        state = dudect_main(&ctx);
        batches++;
        fflush(stdout);
    }
    dudect_free(&ctx);
    /* The executed count is derived from the instrument's own configuration and
     * the number of batches it actually ran (`batches`), not assumed.  A leak
     * verdict stops the loop early, so the total is printed rather than inferred
     * from "3 batches" in the receipt. */
    fprintf(stderr,
            "dudect.executed mode=%s per_batch=%zu batches_run=%d total_measurements=%zu\n",
            m, config.number_measurements, batches,
            (size_t)batches * config.number_measurements);
    fprintf(stderr, "dudect.done mode=%s batches=%d state=%d\n", m, batches, (int)state);
    return (int)state;
}
