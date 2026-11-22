/*
 * dudect harness: BN_mod_exp_mont_consttime, BN_mod_inverse in four
 * configurations, and two comparison controls.
 *
 * WHY THERE ARE FOUR INVERSE MODES
 *
 * The first version of this harness had one `inverse` mode and it did not set
 * BN_FLG_CONSTTIME on either operand, so it measured the *variable-time*
 * dispatch of BN_mod_inverse. It reported a leak verdict (max |t| 485) that was
 * then read as a statement about the constant-time kernel, which it was not: the
 * kernel is selected by that flag. The modes below separate the questions the
 * one mode conflated, and each records which configuration it ran:
 *
 *   inverse_vt      unflagged BN_mod_inverse, operands of DIFFERENT bit length.
 *                   This is deliberately the variable-time path: it is the
 *                   control that must show leakage if the instrument works.
 *   inverse_ct      flagged BN_mod_inverse, operands of EQUAL bit length, so the
 *                   only difference between classes is the value.
 *   inverse_ct_len  flagged BN_mod_inverse, operands of DIFFERENT bit length.
 *                   Whatever this shows is about the public length metadata, not
 *                   about value dependence; it is reported separately for that
 *                   reason.
 *   inverse_ec      flagged BN_mod_inverse modulo the P-256 group order, which
 *                   is the domain the ECDSA signing path uses. The order is
 *                   obtained from the curve via EC_GROUP_get_order, not typed in.
 *
 * WHAT THIS HARNESS CAN AND CANNOT ESTABLISH
 *
 * It records BN_get_flags(a) and BN_get_flags(n) after setup, so it shows the
 * flag was stored. It does not itself prove the constant-time kernel ran: the
 * crate's BN_mod_inverse reads that flag, and the *ctgrind* case
 * `bn::arith::tests::ctgrind_secret_mod_inverse` witnesses the code path by
 * taint, not by timing. The pair of instruments is the evidence; neither alone
 * is. A flagged run therefore also reports the unflagged run beside it, and the
 * receipt must present them together.
 *
 * Every mode checks that the inversion SUCCEEDED (non-NULL) and counts failures;
 * measurements are not accepted when an operation failed, because a failed
 * inversion has its own timing and would silently replace the one being measured.
 *
 * Operands (p = 2^255-19, prime; any non-multiple is invertible):
 *   equal length, differing value : 2^254-3  vs 2^254-5
 *   differing length              : 2^200+1  vs 2^254-3
 *   ECDSA domain (mod n)          : n-3      vs n-5
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
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

enum mode {
    M_MODEXP,
    M_INVERSE_VT,
    M_INVERSE_CT,
    M_INVERSE_CT_LEN,
    M_INVERSE_EC,
    M_CMPCMP,
    M_CMPNAIVE
};
static enum mode g_mode;

static BN_CTX *g_ctx;
static BIGNUM *g_r, *g_a, *g_p, *g_e0, *g_e1;
static BIGNUM *g_same0, *g_same1;   /* equal length, differing value */
static BIGNUM *g_len0, *g_len1;     /* differing length */
static BIGNUM *g_n, *g_ec0, *g_ec1; /* P-256 order and two values below it */
static unsigned char *g_a_buf, *g_first, *g_last;
static unsigned long g_failures;
static unsigned long g_successes;

#define CTL_REPS 32
#define CTL_LEN 4096

static int setup_bn(void)
{
    g_ctx = BN_CTX_new();
    g_r = BN_new(); g_a = BN_new(); g_p = BN_new();
    g_e0 = BN_new(); g_e1 = BN_new();
    g_same0 = BN_new(); g_same1 = BN_new();
    g_len0 = BN_new(); g_len1 = BN_new();
    g_n = BN_new(); g_ec0 = BN_new(); g_ec1 = BN_new();
    if (!g_ctx || !g_r || !g_a || !g_p || !g_e0 || !g_e1 ||
        !g_same0 || !g_same1 || !g_len0 || !g_len1 || !g_n || !g_ec0 || !g_ec1)
        return 0;
    if (!BN_one(g_p) || !BN_lshift(g_p, g_p, 255) || !BN_sub_word(g_p, 19))
        return 0;
    if (!BN_set_word(g_a, 5))
        return 0;
    if (!BN_one(g_e0) || !BN_lshift(g_e0, g_e0, 254) || !BN_add_word(g_e0, 1))
        return 0;
    if (!BN_one(g_e1) || !BN_lshift(g_e1, g_e1, 255) || !BN_sub_word(g_e1, 1))
        return 0;
    /* 2^254-3 and 2^254-5: both 254 bits, so the classes differ only in value. */
    if (!BN_one(g_same0) || !BN_lshift(g_same0, g_same0, 254) || !BN_sub_word(g_same0, 3))
        return 0;
    if (!BN_one(g_same1) || !BN_lshift(g_same1, g_same1, 254) || !BN_sub_word(g_same1, 5))
        return 0;
    /* 2^200+1 and 2^254-3: different bit lengths, for the length mode. */
    if (!BN_one(g_len0) || !BN_lshift(g_len0, g_len0, 200) || !BN_add_word(g_len0, 1))
        return 0;
    if (!BN_copy(g_len1, g_same0))
        return 0;
    return 1;
}

/* The P-256 order, taken from the curve rather than typed in. */
static int setup_ec(void)
{
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (grp == NULL)
        return 0;
    int ok = EC_GROUP_get_order(grp, g_n, g_ctx) == 1;
    EC_GROUP_free(grp);
    if (!ok)
        return 0;
    if (!BN_copy(g_ec0, g_n) || !BN_sub_word(g_ec0, 3))
        return 0;
    if (!BN_copy(g_ec1, g_n) || !BN_sub_word(g_ec1, 5))
        return 0;
    return 1;
}

static void flag_for_ct(void)
{
    /* The crate's BN_mod_inverse reads BN_FLG_CONSTTIME from either operand. */
    BN_set_flags(g_same0, BN_FLG_CONSTTIME);
    BN_set_flags(g_same1, BN_FLG_CONSTTIME);
    BN_set_flags(g_len0, BN_FLG_CONSTTIME);
    BN_set_flags(g_len1, BN_FLG_CONSTTIME);
    BN_set_flags(g_ec0, BN_FLG_CONSTTIME);
    BN_set_flags(g_ec1, BN_FLG_CONSTTIME);
    BN_set_flags(g_p, BN_FLG_CONSTTIME);
    BN_set_flags(g_n, BN_FLG_CONSTTIME);
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
        /* BN_mod_exp_mont_consttime returns int (1/0), not a pointer: the first
         * version of this arm compared it with NULL, which is 0 and therefore
         * happened to count correctly while emitting a pointer/integer warning.
         * Compare with 0 explicitly. */
        if (BN_mod_exp_mont_consttime(g_r, g_a, cls ? g_e1 : g_e0, g_p, g_ctx, NULL) == 0)
            g_failures++;
        else
            g_successes++;
        return 0;
    case M_INVERSE_VT:
        if (BN_mod_inverse(g_r, cls ? g_len1 : g_len0, g_p, g_ctx) == NULL)
            g_failures++;
        else
            g_successes++;
        return 0;
    case M_INVERSE_CT:
        if (BN_mod_inverse(g_r, cls ? g_same1 : g_same0, g_p, g_ctx) == NULL)
            g_failures++;
        else
            g_successes++;
        return 0;
    case M_INVERSE_CT_LEN:
        if (BN_mod_inverse(g_r, cls ? g_len1 : g_len0, g_p, g_ctx) == NULL)
            g_failures++;
        else
            g_successes++;
        return 0;
    case M_INVERSE_EC:
        if (BN_mod_inverse(g_r, cls ? g_ec1 : g_ec0, g_n, g_ctx) == NULL)
            g_failures++;
        else
            g_successes++;
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

static int uses_bn(enum mode m)
{
    return m == M_MODEXP || m == M_INVERSE_VT || m == M_INVERSE_CT ||
           m == M_INVERSE_CT_LEN || m == M_INVERSE_EC;
}

static int mode_needs_flags(enum mode m)
{
    return m == M_INVERSE_CT || m == M_INVERSE_CT_LEN || m == M_INVERSE_EC;
}

int main(int argc, char **argv)
{
    dudect_config_t config = { .chunk_size = 1, .number_measurements = 20000 };
    dudect_ctx_t ctx;
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    const char *m = argc > 1 ? argv[1] : "";
    int batches = 0;

    if (strcmp(m, "modexp") == 0) g_mode = M_MODEXP;
    else if (strcmp(m, "inverse_vt") == 0) g_mode = M_INVERSE_VT;
    else if (strcmp(m, "inverse_ct") == 0) g_mode = M_INVERSE_CT;
    else if (strcmp(m, "inverse_ct_len") == 0) g_mode = M_INVERSE_CT_LEN;
    else if (strcmp(m, "inverse_ec") == 0) g_mode = M_INVERSE_EC;
    else if (strcmp(m, "cmpcmp") == 0) g_mode = M_CMPCMP;
    else if (strcmp(m, "cmpnaive") == 0) g_mode = M_CMPNAIVE;
    else {
        fprintf(stderr,
                "usage: %s modexp|inverse_vt|inverse_ct|inverse_ct_len|inverse_ec|cmpcmp|cmpnaive [measurements]\n",
                argv[0]);
        return 2;
    }

    if (uses_bn(g_mode)) {
        if (!setup_bn()) { fprintf(stderr, "setup_bn failed\n"); return 2; }
        if (g_mode != M_INVERSE_VT) {
            if (!setup_ec()) { fprintf(stderr, "setup_ec failed (EC_GROUP_get_order)\n"); return 2; }
        }
        if (mode_needs_flags(g_mode))
            flag_for_ct();
        /* Read the flag back: this shows the library stored it, which is a
         * precondition of the dispatch, not proof that the CT kernel ran. */
        fprintf(stderr,
                "dudect.flags mode=%s a0=0x%x a1=0x%x modulus=0x%x consttime_bits=0x%x\n",
                m,
                BN_get_flags(g_mode == M_INVERSE_CT ? g_same0 : g_len0, BN_FLG_CONSTTIME),
                BN_get_flags(g_mode == M_INVERSE_CT ? g_same1 : g_len1, BN_FLG_CONSTTIME),
                BN_get_flags(g_mode == M_INVERSE_EC ? g_n : g_p, BN_FLG_CONSTTIME),
                BN_FLG_CONSTTIME);
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
    if (uses_bn(g_mode)) {
        fprintf(stderr, "dudect.ops mode=%s successes=%lu failures=%lu\n",
                m, g_successes, g_failures);
        if (g_failures != 0) {
            fprintf(stderr,
                    "dudect.rejected mode=%s: %lu inversion(s) failed, so these timings "
                    "measure a failure path and are not accepted\n", m, g_failures);
            return 3;
        }
    }
    return (int)state;
}
