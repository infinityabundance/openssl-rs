/*
 * openssl-rs — the ML-DSA correctness probe (CT-ML-DSA).
 *
 * This program is compiled **once**, against the candidate distribution shell alone, and its
 * answers are compared with the authority's published FIPS 204 / ACVP vectors. There is no
 * authority transcript: the differential question — "does the candidate behave like the
 * authority?" — is `RT-KEYMGMT`'s and `RT-SIGNATURE`'s. This is the second, independent plane,
 * and it exists because a differential court only proves agreement: two implementations can
 * agree byte for byte and both be wrong (D400/D406). A published vector closes a derived value.
 *
 * Like `ct_digest.c` and `ct_cipher.c` this driver **computes and never decides**: it prints one
 * result line per vector and returns 0. `forensics/tools/correctness_vectors.py:run_ml_dsa_court`
 * owns the expected values and the comparison, so a defect in this probe cannot be mistaken for a
 * passing vector.
 *
 * Protocol
 * --------
 * No argument. The vectors are compiled in from the generated header `ct_ml_dsa_vectors.h`
 * (see `forensics/tools/gen_ct_ml_dsa_vectors.py`), because a keygen seed is 32 bytes but a
 * signature is up to 4627 and a private key up to 4896: a call file of that size would be a
 * second transcription, and this court's whole point is that a value is *re-read*, not typed.
 * The program writes one line per vector to stdout:
 *
 *     <arm>\t<id>\tok\t<hex>              the operation produced a value
 *     <arm>\t<id>\tok\t<1|0>              the sigver arm's verdict
 *     <arm>\t<id>\terr\t<reason>          the operation refused
 *
 * The tool turns each line into a verdict: a `keygen`/`siggen` line is `sha256` of the produced
 * bytes compared with the vector's committed expected digest; a `sigver` line is the verdict
 * compared with the vector's committed `VERIFY_ERROR`/accept expectation.
 *
 * The three arms
 * --------------
 *   * **keygen** — a key is built through the `OSSL_OP_KEYMGMT` row of the vector's name, the
 *     vector's 32-byte seed is set as `OSSL_PKEY_PARAM_ML_DSA_SEED`, `EVP_PKEY_generate`
 *     produces the key, and the public half is read back with
 *     `EVP_PKEY_get_octet_string_param(..., OSSL_PKEY_PARAM_PUB_KEY, ...)`. Expected: the
 *     vector's byte-identical public key.
 *   * **siggen** — a key is imported from the vector's raw private key through
 *     `EVP_PKEY_fromdata`, the `OSSL_OP_SIGNATURE` row of the same name is fetched, and
 *     `EVP_PKEY_sign_message_init` + `EVP_PKEY_sign` sign the vector's message with
 *     `deterministic = 1` (the signing `rnd` is then 32 zero bytes) and `message-encoding = 1`
 *     (the default pure FIPS 204 encoding) over the vector's context string. Expected: the
 *     vector's byte-identical signature.
 *   * **sigver** — a public key is imported from the vector's raw public key, the row is
 *     fetched, `EVP_PKEY_verify_message_init` + `EVP_PKEY_verify` verify the vector's signature
 *     over its message and context, and the verdict is printed. Expected: the vector's
 *     accept/reject expectation.
 *
 * What this probe deliberately does not observe
 * ---------------------------------------------
 *   * **A randomised signature.** Only the corpus's `deterministic:1` blocks are compiled in:
 *     the others carry a `test-entropy` `rnd`, and printing anything derived from a draw would
 *     make the transcript non-reproducible. The generator records the omission.
 *   * **The external-`mu` interface** (`Ctrl = mu:1`). Those vectors take FIPS 204's 32-byte
 *     message representative as the message and omit the encoding steps; this probe drives the
 *     pure raw-message interface. The generator records the omission, so it is a statement and
 *     not a silent gap.
 *   * **The cut-down `test/ml_dsa.inc` corpus.** It carries only `sha256(signature)` for its
 *     `siggen` items, and is driven with `message-encoding:0`; the `evp_test` corpus is the same
 *     ACVP data at full width. The generator names it in `inputs[]` so the omission is auditable.
 *   * **Any ASN.1 / `SubjectPublicKeyInfo` / DER path.** The vectors are raw keys and
 *     signatures, and the import is `EVP_PKEY_fromdata` over the raw octet strings, so the
 *     `providers/common/der/` encoder is not this court's subject.
 *   * **The `EVP_DigestSign`/`EVP_DigestVerify` wrappers.** The corpus is the
 *     `Sign-Message`/`Verify-Message-Public` external path, which is what `evp_test` drives.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "ct_ml_dsa_vectors.h"

/* The maxima the authority's `include/crypto/ml_dsa.h` declares
 * (`MAX_ML_DSA_PUB_LEN` / `MAX_ML_DSA_PRIV_LEN` / `MAX_ML_DSA_SIG_LEN`, from `ML_DSA_87_*`). */
#define CT_MLDSA_MAX_PUB 2592
#define CT_MLDSA_MAX_PRIV 4896
#define CT_MLDSA_MAX_SIG 4627

static void ct_hex(const unsigned char *bytes, size_t n)
{
    static const char *d = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        putchar(d[bytes[i] >> 4]);
        putchar(d[bytes[i] & 0xf]);
    }
}

static void ct_ok_hex(const char *arm, const char *id, const unsigned char *bytes, size_t n)
{
    printf("%s\t%s\tok\t", arm, id);
    ct_hex(bytes, n);
    putchar('\n');
}

static void ct_ok_int(const char *arm, const char *id, int value)
{
    printf("%s\t%s\tok\t%d\n", arm, id, value);
}

static void ct_err(const char *arm, const char *id, const char *reason)
{
    printf("%s\t%s\terr\t%s\n", arm, id, reason);
}

/* Arm 1 — keygen: fixed seed -> public key, through the keymgmt row. */
static void ct_arm_keygen(void)
{
    size_t i;

    for (i = 0; i < sizeof(ct_mldsa_keygen) / sizeof(ct_mldsa_keygen[0]); i++) {
        const struct ct_mldsa_keygen *v = &ct_mldsa_keygen[i];
        EVP_PKEY_CTX *ctx = NULL;
        EVP_PKEY *pkey = NULL;
        OSSL_PARAM params[2];
        unsigned char pub[CT_MLDSA_MAX_PUB];
        size_t publen = 0;
        int produced = 0;

        ctx = EVP_PKEY_CTX_new_from_name(NULL, v->alg, NULL);
        if (ctx != NULL) {
            params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                          (void *)v->seed, v->seedlen);
            params[1] = OSSL_PARAM_construct_end();
            if (EVP_PKEY_keygen_init(ctx) > 0
                && EVP_PKEY_CTX_set_params(ctx, params) > 0
                && EVP_PKEY_generate(ctx, &pkey) > 0
                && EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub,
                                                   sizeof(pub), &publen) > 0)
                produced = 1;
        }
        if (produced)
            ct_ok_hex("keygen", v->id, pub, publen);
        else
            ct_err("keygen", v->id, "keygen-failed");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
    }
}

/* Arm 2 — siggen: fixed private key + message + context -> deterministic signature. */
static void ct_arm_siggen(void)
{
    size_t i;

    for (i = 0; i < sizeof(ct_mldsa_siggen) / sizeof(ct_mldsa_siggen[0]); i++) {
        const struct ct_mldsa_siggen *v = &ct_mldsa_siggen[i];
        EVP_PKEY_CTX *kctx = NULL;
        EVP_PKEY *pkey = NULL;
        EVP_SIGNATURE *algo = NULL;
        EVP_PKEY_CTX *sctx = NULL;
        OSSL_PARAM kparams[2];
        OSSL_PARAM sparams[4];
        static unsigned char sig[CT_MLDSA_MAX_SIG];
        size_t siglen = sizeof(sig);
        int deterministic = 1;
        int encoding = 1;
        int produced = 0;

        kparams[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                       (void *)v->priv, v->privlen);
        kparams[1] = OSSL_PARAM_construct_end();
        kctx = EVP_PKEY_CTX_new_from_name(NULL, v->alg, NULL);
        if (kctx == NULL || EVP_PKEY_fromdata_init(kctx) <= 0
            || EVP_PKEY_fromdata(kctx, &pkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, kparams) <= 0) {
            ct_err("siggen", v->id, "import-failed");
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(kctx);
            continue;
        }
        algo = EVP_SIGNATURE_fetch(NULL, v->alg, NULL);
        sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        sparams[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                              &deterministic);
        sparams[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encoding);
        sparams[2] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                       (void *)v->ctx, v->ctxlen);
        sparams[3] = OSSL_PARAM_construct_end();
        if (algo != NULL && sctx != NULL
            && EVP_PKEY_sign_message_init(sctx, algo, sparams) > 0
            && EVP_PKEY_sign(sctx, sig, &siglen, v->msg, v->msglen) > 0)
            produced = 1;

        if (produced)
            ct_ok_hex("siggen", v->id, sig, siglen);
        else
            ct_err("siggen", v->id, "sign-failed");
        EVP_SIGNATURE_free(algo);
        EVP_PKEY_CTX_free(sctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(kctx);
    }
}

/* Arm 3 — sigver: public key + message + signature + context -> verdict. */
static void ct_arm_sigver(void)
{
    size_t i;

    for (i = 0; i < sizeof(ct_mldsa_sigver) / sizeof(ct_mldsa_sigver[0]); i++) {
        const struct ct_mldsa_sigver *v = &ct_mldsa_sigver[i];
        EVP_PKEY_CTX *kctx = NULL;
        EVP_PKEY *pkey = NULL;
        EVP_SIGNATURE *algo = NULL;
        EVP_PKEY_CTX *vctx = NULL;
        OSSL_PARAM kparams[2];
        OSSL_PARAM sparams[3];
        int encoding = 1;
        int r = -1;
        int produced = 0;

        kparams[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                       (void *)v->pub, v->publen);
        kparams[1] = OSSL_PARAM_construct_end();
        kctx = EVP_PKEY_CTX_new_from_name(NULL, v->alg, NULL);
        if (kctx == NULL || EVP_PKEY_fromdata_init(kctx) <= 0
            || EVP_PKEY_fromdata(kctx, &pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, kparams) <= 0) {
            ct_err("sigver", v->id, "import-failed");
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(kctx);
            continue;
        }
        algo = EVP_SIGNATURE_fetch(NULL, v->alg, NULL);
        vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        sparams[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encoding);
        sparams[1] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                       (void *)v->ctx, v->ctxlen);
        sparams[2] = OSSL_PARAM_construct_end();
        if (algo != NULL && vctx != NULL
            && EVP_PKEY_verify_message_init(vctx, algo, sparams) > 0) {
            r = EVP_PKEY_verify(vctx, v->sig, v->siglen, v->msg, v->msglen);
            if (r == 0 || r == 1)
                produced = 1;
        }

        if (produced)
            ct_ok_int("sigver", v->id, r);
        else
            ct_err("sigver", v->id, "verify-error");
        EVP_SIGNATURE_free(algo);
        EVP_PKEY_CTX_free(vctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(kctx);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    ct_arm_keygen();
    ct_arm_siggen();
    ct_arm_sigver();
    return 0;
}
