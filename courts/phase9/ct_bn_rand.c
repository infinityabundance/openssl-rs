/*
 * openssl-rs — the CT-BN-RAND construction probe (candidate-only).
 *
 * This program is compiled **once**, against the candidate distribution shell alone, and its
 * answers are compared with committed expected bytes whose provenance is
 * `forensics/vectors/bn_rand_nonce.json`. There is no authority transcript: the differential
 * question — "does the candidate behave like the authority?" — is `RT-BN-RAND`'s, and it is
 * unanswerable for a draw (two machines seed from different pools). This is the second,
 * independent plane, and it exists because the one function in `crypto/bn/bn_rand.c` whose body is
 * a *construction* rather than a draw — `ossl_bn_gen_dsa_nonce_fixed_top` (`:293-395`) and its
 * export `BN_generate_dsa_nonce` (`:397-412`) — computes a value from `(range, priv, message,
 * random)`, and the `random` stream is injectable. With a fixed stream the whole output is a pure
 * function of its inputs, and the committed expected bytes are that function re-derived
 * independently in Python (see the generator's header), so a transcription error in the crate
 * cannot move them.
 *
 * The fixed seed, and what it depends on
 * --------------------------------------
 * The default provider publishes `TEST-RAND`. Its `test_rng_set_ctx_params` accepts
 * `OSSL_RAND_PARAM_TEST_ENTROPY`, and with `generate` unset its `generate` copies exactly those
 * bytes out in order (`providers/implementations/rands/test_rng.c.in:88-105`). So the private DRBG
 * is made a `TEST-RAND` *before* the primary is built (the type must be set before the first draw,
 * and the first draw is what builds it), and the committed stream is installed on it with
 * `EVP_RAND_CTX_set_params`. `test/rand_test.c:test_rand` is the pattern this follows.
 *
 * The two seeding lines are printed **first**, as `ct.drbg_type=<0|1>` and `ct.entropy_set=<0|1>`,
 * so a failure of the seeding mechanism is a named line rather than a cascade of wrong values: if
 * either is 0 the vectors below are drawn from a real pool and every one of them is expected to
 * mismatch.
 *
 * Protocol
 * --------
 * No argument. The vectors are compiled in from the generated header `ct_bn_rand_vectors.h` (see
 * `forensics/tools/gen_bn_rand_nonce_vectors.py`), whose `ct_bn_rand_entropy` is consumed
 * sequentially in array order. The program writes to stdout:
 *
 *     ct.drbg_type=<0|1>
 *     ct.entropy_set=<0|1>
 *     ct.<label>=<minimal big-endian hex of the nonce>   one line per vector
 *     ct.done=1
 *
 * and on a refusal it writes `ct.<label>=error` instead of a hex value. `BN_bn2bin`'s encoding is
 * the minimal big-endian byte string, which is always even-length — a value whose top nibble is
 * zero leads with a `0` nibble there — which is exactly what the vector file's `expected` holds.
 *
 * What this probe deliberately does not observe
 * ---------------------------------------------
 *   * **The expected value.** The runner owns it and the comparison; this program computes and
 *     never decides, so a defect in it cannot be mistaken for a passing vector.
 *   * **Anything through a `BN_CTX`.** `BN_generate_dsa_nonce` is called with a NULL context, so
 *     `ossl_bn_get_libctx` answers NULL and the draw reaches the NULL-`OSSL_LIB_CTX` private DRBG
 *     the entropy was installed on. A live `BN_CTX` would reach a different (equal) handle and is
 *     not observed here.
 *   * **The failure arms.** `BN_R_PRIVATE_KEY_TOO_LARGE`, `BN_R_NO_SUITABLE_DIGEST` and the
 *     `RAND_priv_bytes_ex` refusal are not reachable with a valid 96-byte-fitting key and a
 *     committed stream longer than any draw.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "ct_bn_rand_vectors.h"

/* The widest nonce any vector can produce is one byte narrower than `num_k_bytes`, so 128 bytes
 * covers the 80-byte `wide_range_two_digest` with room to spare. */
#define CT_BN_RAND_MAX_OUT 128

static void ct_hex(const unsigned char *bytes, size_t n)
{
    static const char *d = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        putchar(d[bytes[i] >> 4]);
        putchar(d[bytes[i] & 0xf]);
    }
}

int main(void)
{
    EVP_RAND_CTX *privctx;
    OSSL_PARAM params[2];
    int drbg_type;
    int entropy_set = 0;
    size_t i;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Before the first draw: `RAND_set_DRBG_type` refuses once the primary exists, and the primary
     * is built by the first draw, not by `RAND_get0_private`. */
    drbg_type = RAND_set_DRBG_type(NULL, "TEST-RAND", NULL, NULL, NULL) != 0;
    printf("ct.drbg_type=%d\n", drbg_type);

    privctx = RAND_get0_private(NULL);
    if (privctx != NULL) {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_RAND_PARAM_TEST_ENTROPY, (void *)ct_bn_rand_entropy,
            sizeof(ct_bn_rand_entropy));
        params[1] = OSSL_PARAM_construct_end();
        entropy_set = EVP_RAND_CTX_set_params(privctx, params) > 0;
    }
    printf("ct.entropy_set=%d\n", entropy_set);

    for (i = 0; i < sizeof(ct_bn_rand_vectors) / sizeof(ct_bn_rand_vectors[0]); i++) {
        const struct ct_bn_rand_vector *v = &ct_bn_rand_vectors[i];
        BIGNUM *range = BN_bin2bn(v->range, (int)v->range_len, NULL);
        BIGNUM *priv = BN_bin2bn(v->priv, (int)v->priv_len, NULL);
        BIGNUM *out = BN_new();
        unsigned char outbuf[CT_BN_RAND_MAX_OUT];
        int nbytes = 0;
        int produced;

        produced = range != NULL && priv != NULL && out != NULL
                   && BN_generate_dsa_nonce(out, range, priv, v->message,
                                            v->message_len, NULL) == 1;

        printf("ct.%s=", v->label);
        if (produced && (nbytes = BN_num_bytes(out)) > 0
            && (size_t)nbytes <= sizeof(outbuf)) {
            BN_bn2bin(out, outbuf);
            ct_hex(outbuf, (size_t)nbytes);
        } else {
            printf("error");
        }
        printf("\n");

        BN_free(out);
        BN_free(priv);
        BN_free(range);
    }

    printf("ct.done=1\n");
    return 0;
}
