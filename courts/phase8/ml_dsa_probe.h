/*
 * The fixed ML-DSA keygen seed shared by `rt_keymgmt_probe.c`'s `arm_ml_dsa_keymgmt` and
 * `rt_signature_probe.c`'s `arm_ml_dsa_rows`.
 *
 * ## These are *differential* inputs, not published vectors
 *
 * A differential court compiles one probe twice -- once against the admitted authority, once
 * against the candidate distribution shell -- and diffs the two `key=value` transcripts. Both
 * sides therefore receive the **same** seed, and what the court measures is *this*
 * implementation's behaviour on it: the keypair it derives, the sizes and category it reports,
 * and the deterministic signature it makes. It does **not** measure whether either side agrees
 * with a published known answer -- that independent plane is a *correctness* court's job, and it
 * is a separate court on purpose (`docs/PHASE-8-SUBPHASES.md` §2: an `RT-*` pass is not
 * independent cryptographic correctness, and a `CT-*` pass is not OpenSSL parity). Nothing below
 * is read back from the authority's own test data; a 32-byte seed is the whole of the input the
 * two arms need, and its only property that matters is that both sides see it.
 *
 * ## Why the arms derive from a seed and never from randomness
 *
 * A generated ML-DSA keypair is a function of its keygen seed alone, and a randomised ML-DSA
 * signature is a function of the key and the signing `rnd` alone. The two arms fix both: this
 * seed for keygen, and the provider's own `deterministic=1` signing knob -- which zeroes the
 * signing `rnd` (`src/provider/ml_dsa_sig.rs`, `ml_dsa_sign`/`ml_dsa_sign_msg_final`) -- so a key
 * or a signature produced on the authority and the same one produced on the candidate are
 * byte-identical, and the sha256 of a public key or a signature can be printed without the
 * transcript depending on a draw.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef OSSL_RS_ML_DSA_PROBE_H
#define OSSL_RS_ML_DSA_PROBE_H

#include <stddef.h>

/* A fixed 32-byte `(rho, K)` keygen seed -- `ML_DSA_SEED_BYTES` -- passed as the `seed` gen
 * parameter (`OSSL_PKEY_PARAM_ML_DSA_SEED`) to each of the three parameter sets. It is the same
 * seed for all three because the court's subject is the *row*, and a different seed per parameter
 * set would only make three transcripts harder to compare for no extra observation. */
static const unsigned char ml_dsa_seed[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

#endif /* OSSL_RS_ML_DSA_PROBE_H */
