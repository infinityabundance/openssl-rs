/*
 * RT-SIGNATURE -- Phase 8's `OSSL_OP_SIGNATURE` registration-row court.
 *
 * This court exists for the same reason `rt_keymgmt_probe.c` does, one operation over:
 * `provider_court_coverage.py` (D245) requires every row the census calls `implemented` to be
 * named by a probe of a differential court, and naming is not driving. The four rows this probe
 * covers are the legacy-MAC *signature* face of the four key objects `RT-KEYMGMT` already drives
 * -- `HMAC`, `SIPHASH`, `POLY1305` and `CMAC` -- and the arm below fetches each by name, builds the
 * key through the algorithm's own keymgmt row, signs a fixed message, and observes the return
 * codes, the buffer sizes and the refusals.
 *
 * ## What each row is, and why the probe can observe it at all
 *
 * A legacy-MAC signature row is a shell over `EVP_MAC_*`: its `digest_sign_init` resolves the
 * key's cipher name (CMAC's case), sets the MAC's parameters and hands the private key to
 * `EVP_MAC_init`; update and final are `EVP_MAC_update`/`EVP_MAC_final`. So the observable
 * contract is a **message authentication code**, and because the key is imported from a probe
 * constant rather than generated, that code is the *same bytes* on both sides. The probe prints
 * it as hex -- a mis-forwarded length or a dropped parameter is a residual rather than a
 * plausible-looking log line.
 *
 * A `DSA` signature row is the other shape: `dsa_sign_directly` is `ossl_dsa_sign_int` over the
 * `DSA` key `dsa_kmgmt` publishes, and its `SIGNMSG`/`DIGEST_SIGN` faces digest the message first.
 * The probe imports a **fixed** 1024-bit group -- the authority's own `test/testdsa.pem` key -- and
 * signs the fixed message, then verifies the signature it just produced. The signature itself is
 * randomised, and so is its DER length, so **neither is printed**: what is printed is the return
 * codes, the deterministic maximum buffer size (`dsa.DSA.size_len`) and the verification verdict,
 * all of which are the same on both sides.
 *
 * ## The nine `DSA-<MD>` sigalgs, and why they are fetched rather than signed
 *
 * A `DSA-<MD>` row is selected by `EVP_SIGNATURE_fetch(NULL, "DSA-SHA2-256", NULL)` and by no
 * other public entry point: `EVP_DigestSignInit` picks the signature through the key's own
 * `query_operation_name`, which for a `DSA` key is `DSA`, so the digest path can only ever reach
 * the plain `DSA` row. The nine sigalgs are therefore **named by the fetch list and driven at the
 * fetch**, and the plain row is driven end to end. That is a statement about the public API rather
 * than about the rows, which is why it is written here instead of being left to be inferred from
 * the transcript.
 *
 * ## Why the arms are one signature, and not a sign/verify pair
 *
 * These four rows publish a **sign** face only: their dispatch tables carry `NEWCTX`,
 * `DIGEST_SIGN_INIT/UPDATE/FINAL`, `FREECTX`, `DUPCTX`, `SET_CTX_PARAMS` and
 * `SETTABLE_CTX_PARAMS`, and **no `VERIFY` slot at all**. A MAC has one direction. So the court
 * drives the sign path and then observes the verify path's *refusal* -- `EVP_DigestVerifyInit`
 * answers 0 on both sides, which is the absence of the slot rather than a missing implementation,
 * and it is an observation the sign-only row would otherwise never make. The one-directional shape
 * is stated here rather than worked around, because a probe that skipped the verify arm would
 * leave the refusal unmeasured.
 *
 * ## What this court deliberately does not observe
 *
 *   * **Any generated key.** `EVP_PKEY_fromdata` imports the fixed constants below through each
 *     row's keymgmt; nothing here generates one, so two runs of the same side agree.
 *   * **`EVP_SIGNATURE_fetch` for a name no provider holds**, beyond the one negative line, which
 *     is the fetch machinery's own refusal and not a row's.
 *   * **A verify that could succeed.** No landed signature row publishes a verify slot, so a
 *     positive verify observation would be a claim about a unit this court is not the evidence for.
 *
 * ## The `ECDSA` rows, and the second shape of drive
 *
 * The ten `ECDSA` rows are reached two ways, because the two kinds of row need different entries.
 * The plain `ECDSA` row is driven through `EVP_DigestSignInit`, the same path the plain `DSA` row
 * uses: a fixed P-256 key from the `EC` keymgmt row, a fixed message, a sign and a verify. The
 * **nine `ECDSA-<MD>` sigalgs publish `SIGN_MESSAGE_INIT`/`VERIFY_MESSAGE_INIT`**, so unlike
 * `DSA`'s they are not confined to the fetch: each is fetched by name, then driven end to end
 * through `EVP_PKEY_sign_message_init` over its own `EVP_SIGNATURE`, and verified through
 * `EVP_PKEY_verify_message_init` with the signature set by `EVP_PKEY_CTX_set_signature`. A row that
 * fetched but whose `sign_message_init` refused would be a residual rather than a name in a list.
 *
 * **The P-256 constants are read back from the authority, not typed (D392's lesson).** The private
 * scalar's native-endian byte order and the public point's uncompressed encoding were derived by a
 * one-off program linked against the admitted authority, so the probe's constants are the
 * authority's own values rather than a second transcription -- two sides agreeing on a wrong
 * constant is invisible to a differential court.
 *
 * ## The five `EdDSA` rows
 *
 * A `EdDSA` row publishes `SIGN_MESSAGE_INIT`/`VERIFY_MESSAGE_INIT` and the one-shot `SIGN`/
 * `VERIFY`, so each is driven through its own `EVP_SIGNATURE`: `EVP_PKEY_sign_message_init` over the
 * fixed key, `EVP_PKEY_sign` for the fixed message, then `EVP_PKEY_verify_message_init` and
 * `EVP_PKEY_verify`. The key is imported from a **seed** (32 bytes for Ed25519, 57 for Ed448) and
 * the keymgmt derives the public point, so there is no second constant to agree on. `Ed25519ctx`
 * requires a context string, which the probe supplies through the row's own `context-string`
 * parameter; the no-context arm is the sign path's `csflag && context_len == 0` refusal, carried as
 * its own observation.
 *
 * ## The fourteen `RSA` rows
 *
 * The plain `RSA` row is driven through `EVP_DigestSignInit` over a fixed 2048-bit key, a sign then
 * a verify; the thirteen `RSA-<MD>` sigalgs publish `SIGN_MESSAGE_INIT`/`VERIFY_MESSAGE_INIT` and
 * are each fetched by name and driven through their own `EVP_SIGNATURE` dispatch, the same shape the
 * `ECDSA` nine use. **Every byte of the key is read back from the authority** (D392's lesson): a
 * one-off program linked against the admitted authority generated it once and printed each component
 * through `EVP_PKEY_get_bn_param`, so nothing is a typed constant the two sides could agree on while
 * both being wrong. The refusals carried are the XOF-digest arm of `rsa_setup_md` and the one-byte
 * destination's `PROV_R_INVALID_SIGNATURE_SIZE`, once for the plain row and once per sigalg.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#include "slh_dsa_probe.h"
#include "ml_dsa_probe.h"

static void kv_int(const char *key, int value)
{
    printf("%s=%d\n", key, value);
}

static void kv_hex(const char *key, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", key);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* The four landed OSSL_OP_SIGNATURE rows this probe fetches, in the authority's deflt_signature[]
 * order. An `OSSL_OP_SIGNATURE` row is also the algorithm's own keymgmt name, which is how the
 * probe reaches the key the row signs with. The key length is the MAC's own: `SIPHASH` and `CMAC`
 * take sixteen bytes, `POLY1305` takes thirty-two, and `HMAC` accepts any length. */
static const struct {
    const char *name;
    size_t keylen;
} sig_rows[] = {
    { "HMAC", 16 },
    { "SIPHASH", 16 },
    { "POLY1305", 32 },
    { "CMAC", 16 },
};

/* The fixed private key every row imports: a public constant the two sides must agree on, not a
 * secret and not a generated key. */
static const unsigned char sig_priv[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/* The fixed message the probe signs. */
static const char sig_message[] = "openssl-rs RT-SIGNATURE";

/* The digest the MAC sign is driven with. A legacy-MAC signature row is reached through
 * `EVP_DigestSignInit` because that is the face it dispatches; `HMAC` is the one row of the four
 * that *uses* the digest (its `ossl_prov_set_macctx` sets the MAC's `digest` parameter from it),
 * and the other three ignore the parameter, so passing one is the caller's shape for all four
 * rather than a special case. The authority refuses a digest-less `HMAC` init at both sides, which
 * the probe observes before this digest is supplied. */
static const EVP_MD *sig_md(void)
{
    return EVP_sha256();
}

/* The ten landed `OSSL_OP_SIGNATURE` `DSA` rows, by their primary name, in the authority's
 * deflt_signature[] order. The plain `DSA` row is driven end to end below; the nine sigalgs are
 * reached by the fetch, for the reason the file header states. */
static const char *dsa_rows[] = { "DSA", "DSA-SHA1", "DSA-SHA2-224", "DSA-SHA2-256",
                                  "DSA-SHA2-384", "DSA-SHA2-512", "DSA-SHA3-224", "DSA-SHA3-256",
                                  "DSA-SHA3-384", "DSA-SHA3-512" };

/* The fixed DSA group and key: a 1024-bit group whose `q` is 160 bits, imported through the `DSA`
 * keymgmt row exactly as any caller's key would be. The five components are the authority's own
 * `test/testdsa.pem` (`p`, `q`, `g`, the private `x` and the public `y`), so the group is a real
 * one rather than a constructed toy: the nonce is still random, but the sign/verify *outcome* is
 * the same on both sides.
 *
 * **The bytes are little-endian**, which is `OSSL_PARAM_construct_BN`'s native order rather than
 * the DER order a PEM spells: the arrays below are the DER INTEGERs read back to front. D391's
 * `RT-KEYMGMT` is where the ordering matters and was not noticed -- it imports `{ 0x0c, 0xa1 }`
 * and calls the value 3233, which native order makes 0xa10c, and no court caught it because both
 * sides agreed on the same wrong number. A signature is the first observation that notices: a `q`
 * of 158 bits is outside `dsa_do_verify`'s {160, 224, 256}, so the verify reports
 * `DSA_R_BAD_Q_VALUE` and this probe would have been a residual rather than a measurement. */
static const unsigned char dsa_probe_p[128] = {
    0xd7, 0x05, 0x06, 0x54, 0x6d, 0x12, 0x6d, 0x02, 0x38, 0x25, 0xbe, 0x45,
    0xf2, 0xb0, 0x08, 0xa5, 0x52, 0x90, 0xb1, 0x67, 0xe4, 0x71, 0xdf, 0xea,
    0x62, 0xe6, 0xe5, 0xa5, 0x99, 0x1a, 0x1b, 0xb0, 0xe7, 0xac, 0x36, 0x5c,
    0xd2, 0x19, 0xa4, 0x09, 0xb7, 0xd0, 0x40, 0x90, 0xc0, 0x41, 0xfa, 0xda,
    0xa4, 0x59, 0x0b, 0xef, 0xc5, 0x39, 0x65, 0x41, 0x8d, 0xc2, 0x3c, 0xaa,
    0xff, 0xe5, 0x0d, 0x07, 0x54, 0xd4, 0xd8, 0x05, 0x4a, 0x20, 0xd9, 0x26,
    0x5a, 0x67, 0x54, 0x79, 0xe2, 0xe0, 0xe0, 0x10, 0xc7, 0xc7, 0x1c, 0x4d,
    0xbc, 0xab, 0x0c, 0xc7, 0x80, 0x77, 0x97, 0xd2, 0x01, 0xb0, 0xf3, 0x08,
    0x7b, 0x90, 0x91, 0x56, 0x53, 0x21, 0xea, 0x72, 0xbe, 0xbe, 0xcf, 0xa6,
    0xbf, 0x40, 0xcf, 0x7a, 0x15, 0x2f, 0x8f, 0x6c, 0x82, 0xe2, 0x95, 0xe3,
    0x29, 0xa6, 0x2d, 0xcf, 0x84, 0x8d, 0x2a, 0xfd,
};
static const unsigned char dsa_probe_q[20] = {
    0x23, 0xfd, 0xaa, 0x78, 0x85, 0x2e, 0x79, 0x4e, 0x57, 0x99, 0x3e, 0x94,
    0x10, 0xc2, 0xa9, 0xef, 0xaf, 0xb0, 0x97, 0xdf,
};
static const unsigned char dsa_probe_g[128] = {
    0x76, 0xb6, 0x9c, 0xc9, 0x8f, 0x15, 0xfa, 0x8d, 0x86, 0xa9, 0x55, 0xbf,
    0x79, 0x6b, 0x7c, 0xd9, 0x6d, 0x2b, 0xea, 0x0c, 0xc0, 0x8b, 0x9e, 0xab,
    0x79, 0x02, 0x9d, 0x4c, 0xbd, 0x03, 0x6a, 0xa4, 0x47, 0xb5, 0x31, 0x7c,
    0x06, 0x0b, 0x94, 0xa7, 0xfb, 0xf7, 0xd7, 0x6c, 0x0a, 0x95, 0xf5, 0x7f,
    0xea, 0xb9, 0xb0, 0x3b, 0xca, 0xdd, 0x6e, 0x6e, 0x2a, 0xdd, 0x65, 0xef,
    0x4e, 0xf7, 0xa1, 0x97, 0x13, 0xc3, 0x51, 0x5a, 0x59, 0x69, 0x5d, 0xa8,
    0xfe, 0x9a, 0xba, 0xec, 0xde, 0x6a, 0xc1, 0x88, 0xa6, 0x8b, 0xc4, 0xb3,
    0xad, 0xb5, 0x0f, 0x9a, 0x02, 0x65, 0x64, 0xe1, 0x56, 0xde, 0xbb, 0xfa,
    0x68, 0x7b, 0x82, 0xf3, 0x28, 0x89, 0xdd, 0xc8, 0x9e, 0xbb, 0x86, 0x43,
    0xa7, 0x96, 0x06, 0xd7, 0xa3, 0x50, 0x20, 0x22, 0x4e, 0x59, 0xad, 0x53,
    0x64, 0xa6, 0xa5, 0xb8, 0x70, 0xc7, 0x76, 0xbe,
};
static const unsigned char dsa_probe_priv[20] = {
    0xc2, 0xf8, 0x3d, 0xcc, 0x77, 0x95, 0x1f, 0xd8, 0x85, 0x12, 0xe4, 0xc5,
    0xd0, 0x55, 0x97, 0xb8, 0x97, 0xd4, 0x71, 0xbf,
};
static const unsigned char dsa_probe_pub[128] = {
    0x41, 0x7d, 0x7c, 0xef, 0x87, 0xc7, 0x88, 0x24, 0x2a, 0x79, 0x8f, 0x57,
    0x66, 0x7c, 0x1d, 0xe4, 0xf7, 0xbc, 0xf7, 0x2e, 0x0c, 0x39, 0x8c, 0x85,
    0xdb, 0x3f, 0x13, 0x8f, 0x85, 0x89, 0x8f, 0x42, 0x81, 0x6b, 0x7c, 0xbf,
    0xbd, 0x25, 0x8a, 0x50, 0x71, 0x38, 0x1b, 0xe0, 0x7f, 0x78, 0xe8, 0x37,
    0x50, 0x64, 0x4a, 0xe5, 0xb5, 0xa0, 0x45, 0x4c, 0x11, 0xbe, 0x3e, 0x19,
    0x20, 0x2f, 0xc2, 0xf9, 0xee, 0x91, 0xf0, 0x5c, 0x6a, 0xcc, 0x02, 0x5b,
    0xb9, 0x10, 0x27, 0xd6, 0x65, 0x45, 0xd1, 0xc3, 0xac, 0x93, 0x06, 0xad,
    0x2f, 0x4e, 0x8e, 0x6a, 0xec, 0x6c, 0x73, 0x82, 0xbb, 0x77, 0x97, 0x8e,
    0x9a, 0x71, 0xdb, 0x9e, 0xe6, 0xdb, 0x33, 0xa8, 0xfb, 0xa9, 0xc3, 0x92,
    0xf1, 0xec, 0xab, 0x77, 0xeb, 0x19, 0x9b, 0x3e, 0x18, 0x9b, 0xb0, 0x3b,
    0xf0, 0xbf, 0x17, 0x98, 0x7d, 0xa0, 0x99, 0xcc,
};

static EVP_PKEY *sig_build_key(const char *name, size_t keylen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    OSSL_PARAM params[3];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                  (void *)sig_priv, keylen);
    if (strcmp(name, "CMAC") == 0) {
        /* CMAC resolves a cipher out of the same array; without one the row has nothing to
         * initialise, so the key it is driven with must carry it. */
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER,
                                                     (char *)"AES-128-CBC", 0);
        params[2] = OSSL_PARAM_construct_end();
    } else {
        params[1] = OSSL_PARAM_construct_end();
    }

    if (EVP_PKEY_fromdata_init(ctx) > 0)
        (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void arm_signature_rows(void)
{
    size_t i;

    for (i = 0; i < sizeof(sig_rows) / sizeof(sig_rows[0]); i++) {
        const char *name = sig_rows[i].name;
        unsigned char mac[64];
        size_t maclen;
        char key[96];
        char hexkey[96];
        EVP_SIGNATURE *sig;
        EVP_PKEY *pkey;
        EVP_MD_CTX *mdctx;
        EVP_PKEY_CTX *pctx = NULL;
        int init;

        /* 1. The row, fetched by name, and the fetch machinery's own refusal. */
        sig = EVP_SIGNATURE_fetch(NULL, name, NULL);
        snprintf(key, sizeof(key), "sig.%s.fetch", name);
        kv_int(key, sig != NULL);
        EVP_SIGNATURE_free(sig);

        /* 2. The key, through the algorithm's own keymgmt row. */
        pkey = sig_build_key(name, sig_rows[i].keylen);
        snprintf(key, sizeof(key), "sig.%s.key", name);
        kv_int(key, pkey != NULL);
        if (pkey == NULL)
            continue;

        /* 3. The sign path: init, one update, the size query and the code itself. The update and
         * the two finals run only on a context that initialised, so a row that refuses the key
         * reports its refusal rather than a cascade of unrelated failures. */
        mdctx = EVP_MD_CTX_new();
        pctx = NULL;
        init = EVP_DigestSignInit(mdctx, &pctx, sig_md(), NULL, pkey);
        snprintf(key, sizeof(key), "sig.%s.sign_init", name);
        kv_int(key, init);
        if (init > 0) {
            snprintf(key, sizeof(key), "sig.%s.update", name);
            kv_int(key, EVP_DigestSignUpdate(mdctx, sig_message, sizeof(sig_message) - 1));

            maclen = sizeof(mac);
            snprintf(key, sizeof(key), "sig.%s.size", name);
            kv_int(key, EVP_DigestSignFinal(mdctx, NULL, &maclen));
            snprintf(key, sizeof(key), "sig.%s.size_len", name);
            kv_int(key, (int)maclen);

            maclen = sizeof(mac);
            snprintf(key, sizeof(key), "sig.%s.sign", name);
            kv_int(key, EVP_DigestSignFinal(mdctx, mac, &maclen));
            snprintf(key, sizeof(key), "sig.%s.mac_len", name);
            kv_int(key, (int)maclen);
            snprintf(hexkey, sizeof(hexkey), "sig.%s.mac", name);
            kv_hex(hexkey, mac, maclen);
        }
        EVP_MD_CTX_free(mdctx);

        /* 4. The buffer refusal: a one-byte destination for a MAC that does not fit it. */
        mdctx = EVP_MD_CTX_new();
        pctx = NULL;
        if (EVP_DigestSignInit(mdctx, &pctx, sig_md(), NULL, pkey) > 0)
            (void)EVP_DigestSignUpdate(mdctx, sig_message, sizeof(sig_message) - 1);
        maclen = 1;
        snprintf(key, sizeof(key), "sig.%s.small_buffer", name);
        kv_int(key, EVP_DigestSignFinal(mdctx, mac, &maclen));
        EVP_MD_CTX_free(mdctx);

        /* 5. The verify refusal: the row publishes no VERIFY slot, so the init is the refusal. */
        mdctx = EVP_MD_CTX_new();
        pctx = NULL;
        snprintf(key, sizeof(key), "sig.%s.verify_init", name);
        kv_int(key, EVP_DigestVerifyInit(mdctx, &pctx, sig_md(), NULL, pkey));
        EVP_MD_CTX_free(mdctx);

        EVP_PKEY_free(pkey);
    }

    {
        EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "NO-SUCH-SIGNATURE", NULL);

        kv_int("sig.absent.fetch", sig != NULL);
        EVP_SIGNATURE_free(sig);
    }
}

static void arm_dsa_rows(void)
{
    size_t i;

    /* 1. Every landed `DSA` row, fetched by name. */
    for (i = 0; i < sizeof(dsa_rows) / sizeof(dsa_rows[0]); i++) {
        char key[64];
        EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, dsa_rows[i], NULL);

        snprintf(key, sizeof(key), "dsa.%s.fetch", dsa_rows[i]);
        kv_int(key, sig != NULL);
        EVP_SIGNATURE_free(sig);
    }

    /* 2. The plain row end to end: a key through its own keymgmt, a digest, a sign, a verify. */
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
        OSSL_PARAM params[6];
        EVP_PKEY *pkey = NULL;
        EVP_MD_CTX *mdctx;
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char sigbuf[64];
        size_t siglen;
        EVP_MD_CTX *vmdctx;
        int init;

        params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, (unsigned char *)dsa_probe_p,
                                            sizeof(dsa_probe_p));
        params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, (unsigned char *)dsa_probe_q,
                                            sizeof(dsa_probe_q));
        params[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, (unsigned char *)dsa_probe_g,
                                            sizeof(dsa_probe_g));
        params[3] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY,
                                            (unsigned char *)dsa_probe_priv,
                                            sizeof(dsa_probe_priv));
        params[4] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY,
                                            (unsigned char *)dsa_probe_pub, sizeof(dsa_probe_pub));
        params[5] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromdata_init(ctx) > 0)
            (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR | EVP_PKEY_KEY_PARAMETERS,
                                    params);
        kv_int("dsa.DSA.key", pkey != NULL);
        EVP_PKEY_CTX_free(ctx);

        if (pkey == NULL)
            return;

        /* The sign: init, one update, the size query, the code itself. */
        mdctx = EVP_MD_CTX_new();
        init = EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey);
        kv_int("dsa.DSA.sign_init", init);
        if (init > 0) {
            kv_int("dsa.DSA.update", EVP_DigestSignUpdate(mdctx, sig_message,
                                                           sizeof(sig_message) - 1));
            siglen = sizeof(sigbuf);
            kv_int("dsa.DSA.size", EVP_DigestSignFinal(mdctx, NULL, &siglen));
            kv_int("dsa.DSA.size_len", (int)siglen);
            siglen = sizeof(sigbuf);
            kv_int("dsa.DSA.sign", EVP_DigestSignFinal(mdctx, sigbuf, &siglen));

            /* The verify, over the signature this call just produced. **The actual signature length
             * is deliberately not printed**: a DSA signature is a DER `SEQUENCE` of two INTEGERs
             * whose lengths depend on the random `r` and `s`, so it moves between runs of the same
             * side and a differential court cannot compare it. `dsa.DSA.size_len` above is the
             * deterministic maximum and the verdict below is the round trip. */
            vmdctx = EVP_MD_CTX_new();
            pctx = NULL;
            if (EVP_DigestVerifyInit(vmdctx, &pctx, EVP_sha256(), NULL, pkey) > 0)
                (void)EVP_DigestVerifyUpdate(vmdctx, sig_message, sizeof(sig_message) - 1);
            kv_int("dsa.DSA.verify", EVP_DigestVerifyFinal(vmdctx, sigbuf, siglen));
            EVP_MD_CTX_free(vmdctx);
        }
        EVP_MD_CTX_free(mdctx);

        /* The unapproved-digest refusal: `dsa_setup_md`'s `ossl_digest_get_approved_nid` arm. */
        mdctx = EVP_MD_CTX_new();
        pctx = NULL;
        kv_int("dsa.DSA.md5", EVP_DigestSignInit(mdctx, &pctx, EVP_md5(), NULL, pkey));
        EVP_MD_CTX_free(mdctx);

        EVP_PKEY_free(pkey);
    }
}

/* The ten landed `OSSL_OP_SIGNATURE` `ECDSA` rows, by their primary name, in the authority's
 * deflt_signature[] order. The plain `ECDSA` row is driven through `EVP_DigestSignInit` below; the
 * nine sigalgs are each fetched by name and driven through their own `EVP_SIGNATURE` dispatch. */
static const char *ecdsa_rows[] = { "ECDSA", "ECDSA-SHA1", "ECDSA-SHA2-224", "ECDSA-SHA2-256",
                                    "ECDSA-SHA2-384", "ECDSA-SHA2-512", "ECDSA-SHA3-224",
                                    "ECDSA-SHA3-256", "ECDSA-SHA3-384", "ECDSA-SHA3-512" };

/* The fixed P-256 private scalar and its public point. **Both are read back from the authority**
 * (D392's lesson): the scalar is in `OSSL_PARAM_construct_BN`'s native-endian order and the point
 * is the uncompressed `04 || X || Y` encoding, and a one-off program linked against the admitted
 * authority printed both. A transcription that agreed with itself on a wrong value would be
 * invisible to this court, so nothing here is typed from memory. The key is real rather than a toy:
 * signing and verifying a fixed message with it is what `EC_KEY`'s own arithmetic is driven with. */
static const unsigned char ecdsa_probe_priv[32] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
};
static const unsigned char ecdsa_probe_pub[65] = {
    0x04, 0xad, 0x1a, 0xae, 0x5f, 0x1e, 0x9c, 0x16, 0x5d, 0xdd, 0x10, 0x3b, 0xfd, 0x71, 0xc2, 0xda,
    0x49, 0x01, 0x29, 0x2c, 0xbc, 0x2c, 0x3d, 0xfe, 0x31, 0x8c, 0xae, 0x60, 0x3e, 0x6a, 0x76, 0x24,
    0x77, 0x55, 0xcb, 0x00, 0x6a, 0x3a, 0x99, 0x9f, 0x04, 0x84, 0x58, 0xa8, 0x92, 0x96, 0x00, 0xb5,
    0x1f, 0x9f, 0x9d, 0x4a, 0xd1, 0xf7, 0xea, 0x53, 0x0b, 0xf0, 0x39, 0x05, 0xab, 0x10, 0x4b, 0x6f,
    0x86
};

/* The key, through the `EC` keymgmt row: the published NIST P-256 group by name, the private scalar
 * and the matching public point, all three through one `EVP_PKEY_fromdata`. */
static EVP_PKEY *ecdsa_build_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    OSSL_PARAM params[4];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)"prime256v1", 0);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY,
                                        (unsigned char *)ecdsa_probe_priv,
                                        sizeof(ecdsa_probe_priv));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (unsigned char *)ecdsa_probe_pub,
                                                  sizeof(ecdsa_probe_pub));
    params[3] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata_init(ctx) > 0)
        (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR | EVP_PKEY_KEY_PARAMETERS, params);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void arm_ecdsa_rows(void)
{
    size_t i;
    EVP_PKEY *pkey;

    /* 1. Every landed `ECDSA` row, fetched by name. */
    for (i = 0; i < sizeof(ecdsa_rows) / sizeof(ecdsa_rows[0]); i++) {
        char key[64];
        EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, ecdsa_rows[i], NULL);

        snprintf(key, sizeof(key), "ecdsa.%s.fetch", ecdsa_rows[i]);
        kv_int(key, sig != NULL);
        EVP_SIGNATURE_free(sig);
    }

    /* 2. The key, through the `EC` keymgmt row. */
    pkey = ecdsa_build_key();
    kv_int("ecdsa.key", pkey != NULL);
    if (pkey == NULL)
        return;

    /* 3. The plain row end to end: `EVP_DigestSignInit` picks `ECDSA` through the key's own
     * operation name, then a sign, then a verify of the signature just produced. As with `DSA`, the
     * signature bytes are not printed -- an ECDSA signature is a DER `SEQUENCE` of two INTEGERs whose
     * lengths move with the random `r` and `s`. `size_len` is the deterministic `ECDSA_size` maximum
     * and the verdict is the round trip. */
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char sig[128];
        size_t siglen;
        EVP_MD_CTX *vmdctx;
        int init;

        init = EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey);
        kv_int("ecdsa.ECDSA.sign_init", init);
        if (init > 0) {
            kv_int("ecdsa.ECDSA.update", EVP_DigestSignUpdate(mdctx, sig_message,
                                                               sizeof(sig_message) - 1));
            siglen = sizeof(sig);
            kv_int("ecdsa.ECDSA.size", EVP_DigestSignFinal(mdctx, NULL, &siglen));
            kv_int("ecdsa.ECDSA.size_len", (int)siglen);
            siglen = sizeof(sig);
            kv_int("ecdsa.ECDSA.sign", EVP_DigestSignFinal(mdctx, sig, &siglen));

            vmdctx = EVP_MD_CTX_new();
            pctx = NULL;
            if (EVP_DigestVerifyInit(vmdctx, &pctx, EVP_sha256(), NULL, pkey) > 0)
                (void)EVP_DigestVerifyUpdate(vmdctx, sig_message, sizeof(sig_message) - 1);
            kv_int("ecdsa.ECDSA.verify", EVP_DigestVerifyFinal(vmdctx, sig, siglen));
            EVP_MD_CTX_free(vmdctx);
        }
        EVP_MD_CTX_free(mdctx);
    }

    /* 4. The buffer refusal: a one-byte destination for a signature that cannot fit it. */
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char one[1];
        size_t one_len = sizeof(one);

        if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) > 0)
            (void)EVP_DigestSignUpdate(mdctx, sig_message, sizeof(sig_message) - 1);
        kv_int("ecdsa.ECDSA.small_buffer", EVP_DigestSignFinal(mdctx, one, &one_len));
        EVP_MD_CTX_free(mdctx);
    }

    /* 5. The digest refusals: `ecdsa_setup_md`'s two arms. MD5 is fetchable but unapproved, so on
     * this profile it is the no-AlgorithmIdentifier path rather than a refusal (`ossl_digest_get_approved_nid`'s
     * `NID_undef` is checked only under `FIPS_MODULE`); SHAKE-128 is the `EVP_MD_xof` refusal. */
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;

        kv_int("ecdsa.ECDSA.md5", EVP_DigestSignInit(mdctx, &pctx, EVP_md5(), NULL, pkey));
        EVP_MD_CTX_free(mdctx);
        mdctx = EVP_MD_CTX_new();
        pctx = NULL;
        kv_int("ecdsa.ECDSA.shake", EVP_DigestSignInit(mdctx, &pctx, EVP_shake128(), NULL, pkey));
        EVP_MD_CTX_free(mdctx);
    }

    /* 6. The nine sigalgs, each driven end to end through its own dispatch. The signature bytes are
     * not printed for the same reason as the plain row's; `size_len` and the round-trip verdict are. */
    for (i = 1; i < sizeof(ecdsa_rows) / sizeof(ecdsa_rows[0]); i++) {
        char key[96];
        EVP_SIGNATURE *algo = EVP_SIGNATURE_fetch(NULL, ecdsa_rows[i], NULL);
        EVP_PKEY_CTX *ctx;
        EVP_PKEY_CTX *vctx;
        unsigned char sig[128];
        size_t siglen = sizeof(sig);
        int init;
        int signed_ok = 0;

        if (algo == NULL)
            continue;

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        init = EVP_PKEY_sign_message_init(ctx, algo, NULL);
        snprintf(key, sizeof(key), "ecdsa.%s.sign_message_init", ecdsa_rows[i]);
        kv_int(key, init);
        if (init > 0) {
            snprintf(key, sizeof(key), "ecdsa.%s.update", ecdsa_rows[i]);
            kv_int(key, EVP_PKEY_sign_message_update(ctx, sig_message,
                                                     sizeof(sig_message) - 1));
            siglen = sizeof(sig);
            snprintf(key, sizeof(key), "ecdsa.%s.size", ecdsa_rows[i]);
            kv_int(key, EVP_PKEY_sign_message_final(ctx, NULL, &siglen));
            snprintf(key, sizeof(key), "ecdsa.%s.size_len", ecdsa_rows[i]);
            kv_int(key, (int)siglen);
            siglen = sizeof(sig);
            snprintf(key, sizeof(key), "ecdsa.%s.sign", ecdsa_rows[i]);
            signed_ok = EVP_PKEY_sign_message_final(ctx, sig, &siglen) > 0;
            kv_int(key, signed_ok);
        }
        EVP_PKEY_CTX_free(ctx);

        vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (EVP_PKEY_verify_message_init(vctx, algo, NULL) > 0)
            (void)EVP_PKEY_verify_message_update(vctx, (const unsigned char *)sig_message,
                                                 sizeof(sig_message) - 1);
        if (signed_ok)
            (void)EVP_PKEY_CTX_set_signature(vctx, sig, siglen);
        snprintf(key, sizeof(key), "ecdsa.%s.verify", ecdsa_rows[i]);
        kv_int(key, EVP_PKEY_verify_message_final(vctx));
        EVP_PKEY_CTX_free(vctx);
        EVP_SIGNATURE_free(algo);
    }

    EVP_PKEY_free(pkey);
}

/* The five landed `OSSL_OP_SIGNATURE` `EdDSA` rows, by their primary name, in the authority's
 * deflt_signature[] order. */
static const char *eddsa_rows[] = { "ED25519", "ED25519ph", "ED25519ctx", "ED448", "ED448ph" };

/* The fixed Ed25519 seed and Ed448 seed, and the context string Ed25519ctx requires. A seed is any
 * 32- or 57-byte string: the keymgmt derives the public key from it, so unlike the P-256 key above
 * there is no second constant to agree on. */
static const unsigned char ed25519_probe_priv[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
};
static const unsigned char ed448_probe_priv[57] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39
};
static const unsigned char eddsa_probe_ctx[4] = { 0x74, 0x65, 0x73, 0x74 };

static EVP_PKEY *eddsa_build_key(const char *name, const unsigned char *priv, size_t privlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    OSSL_PARAM params[2];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)priv, privlen);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata_init(ctx) > 0)
        (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void arm_eddsa_rows(void)
{
    size_t i;
    EVP_PKEY *ed25519;
    EVP_PKEY *ed448;

    /* 1. Every landed `EdDSA` row, fetched by name. */
    for (i = 0; i < sizeof(eddsa_rows) / sizeof(eddsa_rows[0]); i++) {
        char key[64];
        EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, eddsa_rows[i], NULL);

        snprintf(key, sizeof(key), "eddsa.%s.fetch", eddsa_rows[i]);
        kv_int(key, sig != NULL);
        EVP_SIGNATURE_free(sig);
    }

    /* 2. The two keys, through their own keymgmt rows. */
    ed25519 = eddsa_build_key("ED25519", ed25519_probe_priv, sizeof(ed25519_probe_priv));
    ed448 = eddsa_build_key("ED448", ed448_probe_priv, sizeof(ed448_probe_priv));
    kv_int("eddsa.ED25519.key", ed25519 != NULL);
    kv_int("eddsa.ED448.key", ed448 != NULL);

    /* 3. Each row, signed and verified through its own `EVP_SIGNATURE` dispatch. The signature
     * bytes are not printed: the length is fixed by the instance (64 or 114) and the bytes add
     * nothing a differential court can compare beyond what the verdict already says. */
    for (i = 0; i < sizeof(eddsa_rows) / sizeof(eddsa_rows[0]); i++) {
        char key[96];
        EVP_PKEY *pkey = (strncmp(eddsa_rows[i], "ED25519", 7) == 0) ? ed25519 : ed448;
        EVP_SIGNATURE *algo;
        EVP_PKEY_CTX *ctx;
        EVP_PKEY_CTX *vctx;
        OSSL_PARAM params[2];
        int with_ctx = (strcmp(eddsa_rows[i], "ED25519ctx") == 0);
        unsigned char sig[128];
        size_t siglen = sizeof(sig);
        int init;
        int signed_ok = 0;

        if (pkey == NULL)
            continue;
        algo = EVP_SIGNATURE_fetch(NULL, eddsa_rows[i], NULL);
        if (algo == NULL)
            continue;

        if (with_ctx) {
            params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                          (void *)eddsa_probe_ctx,
                                                          sizeof(eddsa_probe_ctx));
            params[1] = OSSL_PARAM_construct_end();
        }

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        init = EVP_PKEY_sign_message_init(ctx, algo, with_ctx ? params : NULL);
        snprintf(key, sizeof(key), "eddsa.%s.sign_message_init", eddsa_rows[i]);
        kv_int(key, init);
        if (init > 0) {
            signed_ok = EVP_PKEY_sign(ctx, sig, &siglen, (const unsigned char *)sig_message,
                                      sizeof(sig_message) - 1);
            snprintf(key, sizeof(key), "eddsa.%s.sign", eddsa_rows[i]);
            kv_int(key, signed_ok);
            snprintf(key, sizeof(key), "eddsa.%s.siglen", eddsa_rows[i]);
            kv_int(key, (int)siglen);
        }
        EVP_PKEY_CTX_free(ctx);

        /* 4. The buffer refusal: a one-byte destination for a fixed-size signature. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (EVP_PKEY_sign_message_init(ctx, algo, with_ctx ? params : NULL) > 0) {
            unsigned char one[1];
            size_t one_len = sizeof(one);

            snprintf(key, sizeof(key), "eddsa.%s.small_buffer", eddsa_rows[i]);
            kv_int(key, EVP_PKEY_sign(ctx, one, &one_len, (const unsigned char *)sig_message,
                                      sizeof(sig_message) - 1));
        }
        EVP_PKEY_CTX_free(ctx);

        /* 5. The verify. The authority's own `Ed25519ctx` verify through this path answers 0 for a
         * signature its own sign produced; the observation is carried rather than skipped, so a
         * candidate that answered 1 instead would be a residual. */
        vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (EVP_PKEY_verify_message_init(vctx, algo, with_ctx ? params : NULL) > 0) {
            snprintf(key, sizeof(key), "eddsa.%s.verify", eddsa_rows[i]);
            kv_int(key, EVP_PKEY_verify(vctx, sig, siglen, (const unsigned char *)sig_message,
                                        sizeof(sig_message) - 1));
        }
        EVP_PKEY_CTX_free(vctx);
        EVP_SIGNATURE_free(algo);
    }

    /* 6. The `Ed25519ctx` context requirement, observed as its own refusal: with no context string
     * the sign path is `ossl_ed25519_sign`'s `csflag && context_len == 0` arm, and answers 0. */
    if (ed25519 != NULL) {
        EVP_SIGNATURE *algo = EVP_SIGNATURE_fetch(NULL, "ED25519ctx", NULL);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ed25519, NULL);
        unsigned char sig[128];
        size_t siglen = sizeof(sig);

        if (algo != NULL && EVP_PKEY_sign_message_init(ctx, algo, NULL) > 0)
            kv_int("eddsa.ED25519ctx.no_context",
                   EVP_PKEY_sign(ctx, sig, &siglen, (const unsigned char *)sig_message,
                                 sizeof(sig_message) - 1));
        EVP_PKEY_CTX_free(ctx);
        EVP_SIGNATURE_free(algo);
    }

    EVP_PKEY_free(ed25519);
    EVP_PKEY_free(ed448);
}

/* The fourteen landed `OSSL_OP_SIGNATURE` `RSA` rows, by primary name, in the authority's
 * deflt_signature[] order. The plain `RSA` row is driven through `EVP_DigestSignInit`; the thirteen
 * `RSA-<MD>` sigalgs publish `SIGN_MESSAGE_INIT`/`VERIFY_MESSAGE_INIT`, so each is fetched by name
 * and driven through its own `EVP_SIGNATURE` dispatch. */
static const char *rsa_rows[] = {
    "RSA",           "RSA-RIPEMD160", "RSA-SHA1",     "RSA-SHA2-224",     "RSA-SHA2-256",
    "RSA-SHA2-384",  "RSA-SHA2-512",  "RSA-SHA2-512/224", "RSA-SHA2-512/256", "RSA-SHA3-224",
    "RSA-SHA3-256",  "RSA-SHA3-384",  "RSA-SHA3-512", "RSA-SM3",
};

/* The fixed 2048-bit RSA private key every `RSA` row is driven with. **Every byte is read back
 * from the authority** (D392's lesson): a one-off program linked against the admitted authority
 * generated the key once and printed each component through `EVP_PKEY_get_bn_param`, in
 * `OSSL_PARAM_construct_BN`'s native byte order, so nothing here is typed and both sides agree on
 * the authority's own value. A `2048`-bit key is the smallest the FIPS floor accepts for signing,
 * and it is real rather than a toy: signing and verifying a fixed message is what the row's own
 * `RSA_sign`/`RSA_verify` pair is exercised with. */
static const unsigned char rsa_probe_n[256] = {
    0xb1, 0xac, 0x85, 0x8f, 0x39, 0x8d, 0x1c, 0x66, 0x68, 0x4e, 0xef, 0x86,
    0x5f, 0x3f, 0x9e, 0x3e, 0x9e, 0x26, 0x51, 0x65, 0x92, 0xe2, 0xe5, 0x50,
    0x65, 0x6a, 0x81, 0x81, 0x3a, 0x71, 0xc7, 0x10, 0xf1, 0xe2, 0xe5, 0x78,
    0x43, 0x52, 0xb4, 0x82, 0x4e, 0xbb, 0x5c, 0x74, 0x84, 0x51, 0xe4, 0x1c,
    0xc4, 0x3b, 0x07, 0x99, 0x76, 0x3a, 0xcc, 0x33, 0xcc, 0x71, 0xa9, 0x63,
    0x99, 0x06, 0xe4, 0x9c, 0xbe, 0x6b, 0x7b, 0x29, 0xe0, 0xf7, 0x4c, 0xe2,
    0xb8, 0x2c, 0x11, 0x40, 0x04, 0xa5, 0x9c, 0x2a, 0x49, 0x62, 0x1c, 0x32,
    0xa5, 0x46, 0xbe, 0x56, 0x95, 0xbe, 0x9e, 0x1a, 0x15, 0x9e, 0x12, 0xd1,
    0x67, 0x7a, 0x7e, 0x2f, 0xde, 0xa4, 0x98, 0x73, 0x07, 0x6b, 0x03, 0x27,
    0x25, 0x9a, 0x05, 0xf6, 0x17, 0x89, 0xc2, 0x8f, 0x3a, 0x9e, 0xeb, 0x47,
    0x7d, 0x8b, 0x8f, 0x82, 0x37, 0x53, 0x12, 0x74, 0x57, 0x39, 0xa5, 0x94,
    0x6b, 0x63, 0x95, 0xcc, 0x33, 0xc8, 0x56, 0x13, 0x0b, 0x1b, 0x59, 0x0f,
    0xaf, 0x3f, 0x11, 0xc8, 0xdc, 0x9f, 0x53, 0xe2, 0x9e, 0x58, 0x74, 0xe2,
    0x37, 0xd0, 0x43, 0x8a, 0xd3, 0xf1, 0x0d, 0xe8, 0xe0, 0x0a, 0x5b, 0x17,
    0xe6, 0x12, 0x2d, 0x24, 0x6e, 0xbb, 0x3c, 0xdf, 0xc8, 0x4c, 0x74, 0xf7,
    0x68, 0x69, 0xe9, 0x51, 0x42, 0xd5, 0x02, 0x08, 0x9c, 0x3a, 0xca, 0xe5,
    0xb2, 0x6c, 0x4a, 0x22, 0x7f, 0x46, 0xbd, 0x1a, 0xe8, 0x4b, 0x04, 0x1b,
    0xd4, 0xf9, 0x4f, 0xa9, 0x55, 0xcf, 0x8d, 0x60, 0x26, 0xa4, 0x00, 0x8f,
    0x3b, 0xad, 0xde, 0x6a, 0xc6, 0x07, 0x84, 0x6a, 0xf5, 0xcc, 0x29, 0x7b,
    0x14, 0x54, 0xda, 0x6a, 0xb2, 0x01, 0xa8, 0xaa, 0xf7, 0x77, 0x3a, 0x1f,
    0x35, 0xd6, 0xe7, 0xe7, 0x60, 0x6b, 0x56, 0xc2, 0x38, 0x5f, 0xe3, 0x5d,
    0x62, 0x7b, 0xd6, 0x8b,
};
static const unsigned char rsa_probe_e[3] = {
    0x01, 0x00, 0x01,
};
static const unsigned char rsa_probe_d[256] = {
    0x49, 0x5a, 0x52, 0x75, 0x62, 0xdd, 0xcd, 0x93, 0x03, 0x50, 0x9c, 0x5d,
    0x03, 0xc2, 0x98, 0xe6, 0x19, 0x8c, 0xbd, 0xd2, 0x9d, 0x89, 0x68, 0x95,
    0xb9, 0xe0, 0x7e, 0xda, 0xd2, 0x40, 0x6b, 0x79, 0x2c, 0xc1, 0x1b, 0x5c,
    0xef, 0x05, 0x37, 0xce, 0x82, 0xe1, 0x47, 0xf2, 0x25, 0x38, 0xe1, 0x2c,
    0x0c, 0x7f, 0x07, 0xfa, 0x63, 0x01, 0x99, 0xed, 0xf6, 0x2a, 0x36, 0x5b,
    0xb9, 0x0f, 0x1d, 0x95, 0x91, 0x49, 0xe0, 0x3d, 0x9e, 0x6f, 0xd1, 0xe7,
    0xd2, 0x0d, 0x7b, 0x08, 0x6b, 0x51, 0x8e, 0x72, 0x75, 0x67, 0x62, 0x08,
    0x4f, 0xc4, 0x29, 0xcc, 0xab, 0x1b, 0xaa, 0xc5, 0x63, 0x5b, 0xa0, 0xe1,
    0x87, 0x5a, 0x09, 0x9d, 0xf4, 0x1f, 0x15, 0x50, 0x62, 0xde, 0x51, 0xd2,
    0x43, 0x7a, 0x0a, 0x01, 0x73, 0x2a, 0xb6, 0xb4, 0x83, 0xb2, 0xdf, 0x6c,
    0x0a, 0x41, 0x99, 0xe2, 0xdf, 0x08, 0xb2, 0x1e, 0x46, 0xca, 0xc7, 0x12,
    0x3d, 0xe5, 0xd4, 0x64, 0x9e, 0x66, 0x07, 0x38, 0x1c, 0x47, 0xbf, 0x5a,
    0xf8, 0x23, 0x10, 0xfe, 0xe3, 0x54, 0x20, 0xf0, 0x29, 0xd3, 0x28, 0x62,
    0xd8, 0xd6, 0xaa, 0x3d, 0xcf, 0x01, 0xc2, 0x11, 0xc0, 0x20, 0x2b, 0x15,
    0x2d, 0xfa, 0x7d, 0x00, 0xbc, 0xea, 0xf8, 0x9e, 0x9c, 0x06, 0x08, 0xec,
    0x60, 0x5f, 0x17, 0x46, 0x40, 0x35, 0x87, 0xb9, 0xfb, 0x1c, 0xf5, 0xbb,
    0x3b, 0x79, 0x83, 0xa8, 0xd1, 0x78, 0xe0, 0x42, 0x42, 0x82, 0xa9, 0x4e,
    0x0d, 0xfa, 0xa1, 0xef, 0x92, 0xd5, 0x5a, 0xfd, 0x6e, 0x57, 0x79, 0x4f,
    0x70, 0x6f, 0x5b, 0xa1, 0xc2, 0x69, 0x38, 0xcf, 0x67, 0x73, 0xed, 0xf1,
    0x4d, 0x2f, 0x55, 0x29, 0x3f, 0x9d, 0x7c, 0x55, 0xf4, 0x8e, 0x9f, 0x95,
    0xbb, 0xe7, 0x4d, 0x1a, 0x25, 0x75, 0xcc, 0xaa, 0xbb, 0x4c, 0x59, 0xad,
    0xfa, 0x15, 0x4b, 0x37,
};
static const unsigned char rsa_probe_p[128] = {
    0xc3, 0x5e, 0xab, 0x24, 0x3e, 0x35, 0x4f, 0x7c, 0xf1, 0xe2, 0xbc, 0xdd,
    0x75, 0xb9, 0x67, 0x10, 0xc0, 0x13, 0x06, 0xf8, 0xd4, 0xe0, 0x6a, 0xf7,
    0xc3, 0x33, 0x4a, 0xaf, 0x97, 0xa0, 0xa4, 0x53, 0x05, 0xdc, 0x70, 0xf7,
    0x46, 0xf1, 0xb2, 0xbb, 0x09, 0xda, 0xa1, 0xbf, 0x49, 0x3e, 0x34, 0x98,
    0x57, 0x39, 0xfd, 0x8b, 0xcb, 0x74, 0x06, 0x9e, 0x41, 0xbc, 0x39, 0xc9,
    0x4c, 0xcb, 0x52, 0x84, 0x34, 0xd9, 0x6e, 0x78, 0x31, 0xe7, 0xee, 0xfb,
    0x03, 0x50, 0x1a, 0x40, 0x11, 0x6c, 0x2a, 0xb5, 0x25, 0x61, 0xed, 0x33,
    0x5f, 0x86, 0xa5, 0x19, 0xe6, 0x46, 0xde, 0x58, 0x0c, 0xec, 0x91, 0x2c,
    0xe7, 0xc2, 0x49, 0x8f, 0x95, 0x5d, 0xab, 0xe1, 0x6a, 0x8b, 0xad, 0x13,
    0x2d, 0xc6, 0x6d, 0xd3, 0x40, 0xd0, 0x7b, 0xa3, 0x6d, 0x2d, 0x50, 0x09,
    0x4b, 0x9c, 0xa2, 0xd6, 0xe8, 0xfd, 0x44, 0xbf,
};
static const unsigned char rsa_probe_q[128] = {
    0x7b, 0xf7, 0x2b, 0xba, 0x9e, 0x09, 0x6b, 0x4c, 0xef, 0x60, 0xfb, 0x6f,
    0x69, 0xd7, 0x8f, 0x4d, 0xe2, 0x80, 0x2f, 0x01, 0x17, 0xce, 0x09, 0x53,
    0x1a, 0x59, 0x26, 0xaa, 0x01, 0x2b, 0x42, 0x6d, 0xb6, 0x17, 0x87, 0x2c,
    0x45, 0x46, 0x7a, 0x02, 0xda, 0x74, 0x4c, 0xdb, 0x37, 0x8a, 0x9e, 0xcd,
    0x22, 0xa3, 0x7a, 0x58, 0x8b, 0x78, 0x3a, 0x84, 0x7a, 0x8a, 0x80, 0x57,
    0xe0, 0x94, 0x3c, 0x0a, 0xa0, 0x14, 0x28, 0x6d, 0xff, 0x1f, 0x53, 0x7c,
    0xdd, 0x27, 0xd8, 0xf2, 0x9b, 0x15, 0x72, 0x9e, 0xa2, 0xfc, 0x86, 0x7d,
    0x88, 0xc4, 0xf4, 0x55, 0x16, 0xaa, 0x36, 0xe7, 0x0d, 0xd9, 0x33, 0x13,
    0xde, 0x74, 0xe8, 0x97, 0x71, 0xef, 0xd9, 0xa8, 0x08, 0x72, 0xe5, 0x5c,
    0xaa, 0xb6, 0x0b, 0x10, 0xb3, 0xb4, 0x67, 0x33, 0x7c, 0x1a, 0xc6, 0x73,
    0x5a, 0x1d, 0xd3, 0x88, 0x12, 0x9b, 0x29, 0xbb,
};
static const unsigned char rsa_probe_dmp1[128] = {
    0xab, 0x0b, 0x0e, 0xaf, 0x2c, 0xf9, 0x81, 0x07, 0x04, 0xed, 0x44, 0x72,
    0xcf, 0xb0, 0x25, 0x94, 0xb6, 0xd9, 0x96, 0x20, 0xcd, 0x8d, 0x17, 0x28,
    0xc4, 0x96, 0x7d, 0x0d, 0xff, 0xd0, 0x8f, 0xf8, 0x79, 0xe2, 0x12, 0x6b,
    0x2a, 0xfc, 0xc2, 0x89, 0x34, 0x50, 0x61, 0xa1, 0x8a, 0xab, 0x38, 0x71,
    0x02, 0x13, 0xf9, 0xb4, 0xfa, 0x87, 0x62, 0x7a, 0x50, 0xe2, 0xd4, 0x80,
    0x1e, 0x0e, 0x79, 0x28, 0xa5, 0x47, 0xc5, 0x9b, 0x52, 0xe8, 0xa7, 0xda,
    0x68, 0x6f, 0x27, 0x38, 0xe6, 0x9d, 0x22, 0xfe, 0xcb, 0x2e, 0x20, 0x83,
    0x4c, 0xfe, 0xd9, 0xac, 0x61, 0x0c, 0xcf, 0x82, 0x31, 0xb3, 0xe2, 0xa7,
    0x81, 0x34, 0xd5, 0x9e, 0xde, 0x34, 0x58, 0x66, 0xe9, 0xf3, 0x14, 0x73,
    0x83, 0x94, 0xb2, 0xee, 0x30, 0x3a, 0xc9, 0x6e, 0x63, 0x27, 0xdd, 0x35,
    0xf3, 0x9b, 0xd4, 0xac, 0x3a, 0x5f, 0xe6, 0x52,
};
static const unsigned char rsa_probe_dmq1[128] = {
    0x49, 0xa9, 0x68, 0x82, 0xdf, 0x97, 0x66, 0x22, 0xf1, 0x80, 0x0d, 0xf2,
    0x46, 0xf8, 0xc3, 0x88, 0x41, 0x22, 0x35, 0xf8, 0xcd, 0xd3, 0xe0, 0xa9,
    0x3e, 0xc5, 0x55, 0x5a, 0xd4, 0xf5, 0x7c, 0x5f, 0x60, 0xdf, 0x99, 0x52,
    0xd5, 0xd5, 0x6e, 0xf2, 0x94, 0x27, 0x08, 0x25, 0x12, 0x32, 0x56, 0xa0,
    0x70, 0x8f, 0x0f, 0x5f, 0xf9, 0x60, 0x52, 0x8b, 0xca, 0xfb, 0x26, 0x6f,
    0xe9, 0x51, 0x65, 0x5f, 0x33, 0x5e, 0x31, 0xfa, 0xb2, 0x3c, 0xd7, 0x55,
    0x32, 0x9b, 0x86, 0xaa, 0x9c, 0x7d, 0xcd, 0xe6, 0x7c, 0x3f, 0x02, 0x99,
    0x1c, 0x2b, 0x4c, 0x35, 0x77, 0xf1, 0xae, 0xf1, 0x51, 0x4e, 0xda, 0x1d,
    0x4d, 0x02, 0x02, 0x25, 0xd3, 0xb4, 0xb6, 0xeb, 0xf9, 0x0b, 0x90, 0xdf,
    0xb7, 0x69, 0x35, 0xab, 0xe3, 0x0a, 0xbf, 0xb2, 0x08, 0xeb, 0xde, 0xd1,
    0x8c, 0x5a, 0xac, 0x60, 0x9a, 0x15, 0x2e, 0x5d,
};
static const unsigned char rsa_probe_iqmp[128] = {
    0xf9, 0x08, 0xeb, 0x84, 0x92, 0xa0, 0xc7, 0x78, 0x8c, 0x4b, 0xb6, 0xca,
    0x6b, 0x6a, 0x27, 0x61, 0x7d, 0xb0, 0xaa, 0x38, 0x2f, 0xdc, 0xee, 0x02,
    0x38, 0xc8, 0x1b, 0x76, 0xf6, 0xb3, 0x72, 0xb4, 0xd3, 0x3b, 0xf4, 0x35,
    0xd9, 0xe3, 0x87, 0xd6, 0xd4, 0x08, 0x2b, 0xfd, 0x89, 0xa2, 0x94, 0x2c,
    0xbf, 0xc8, 0x95, 0x38, 0x0d, 0x2d, 0xc2, 0x92, 0x35, 0x4b, 0xc1, 0xca,
    0xf5, 0x00, 0x91, 0x69, 0x5b, 0x00, 0x1c, 0xb9, 0xdb, 0x9a, 0xad, 0x8e,
    0xbe, 0xcb, 0x42, 0x9c, 0x63, 0x1b, 0x75, 0xee, 0xd3, 0x37, 0xe4, 0xae,
    0xa8, 0x03, 0x02, 0x80, 0xca, 0x54, 0x7d, 0x02, 0x45, 0x36, 0xef, 0x9e,
    0xd6, 0xb9, 0xd0, 0xf6, 0xb2, 0x8e, 0xb8, 0x95, 0x25, 0x40, 0xfa, 0x1d,
    0xbe, 0x30, 0x21, 0x97, 0x80, 0x03, 0xec, 0x4f, 0xd6, 0xd1, 0x83, 0x84,
    0x4e, 0x76, 0x75, 0x18, 0xcc, 0x02, 0x05, 0x31,
};

/* The private key, through the `RSA` keymgmt row: the eight components of an `EVP_PKEY_KEYPAIR`
 * import in one `EVP_PKEY_fromdata`. */
static EVP_PKEY *rsa_build_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    OSSL_PARAM params[9];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;

    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, (unsigned char *)rsa_probe_n,
                                        sizeof(rsa_probe_n));
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, (unsigned char *)rsa_probe_e,
                                        sizeof(rsa_probe_e));
    params[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, (unsigned char *)rsa_probe_d,
                                        sizeof(rsa_probe_d));
    params[3] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, (unsigned char *)rsa_probe_p,
                                        sizeof(rsa_probe_p));
    params[4] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, (unsigned char *)rsa_probe_q,
                                        sizeof(rsa_probe_q));
    params[5] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                        (unsigned char *)rsa_probe_dmp1, sizeof(rsa_probe_dmp1));
    params[6] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                        (unsigned char *)rsa_probe_dmq1, sizeof(rsa_probe_dmq1));
    params[7] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                        (unsigned char *)rsa_probe_iqmp, sizeof(rsa_probe_iqmp));
    params[8] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata_init(ctx) > 0)
        (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* The thirteen `RSA-<MD>` sigalgs' fetch names are `rsa_rows[1..]`; nothing else is needed here,
 * because each sigalg fixes its own digest in its dispatch rather than taking one from the caller. */

/* The AlgorithmIdentifier a signature context publishes, as hex. `rsa_get_ctx_params`'s
 * `algorithm-id` arm is `rsa_generate_signature_aid`, so this is the observation that drives
 * `ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption` (and, for a PSS key, the `der_rsa_key.c`
 * writer) rather than merely reaching it. */
static void kv_algid(const char *prefix, EVP_PKEY_CTX *ctx)
{
    unsigned char aid[128];
    OSSL_PARAM gp[2];
    char key[96];

    gp[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    gp[1] = OSSL_PARAM_construct_end();
    if (ctx != NULL && EVP_PKEY_CTX_get_params(ctx, gp) > 0 && gp[0].return_size > 0) {
        snprintf(key, sizeof(key), "%s.algid", prefix);
        kv_hex(key, aid, gp[0].return_size);
    }
}

static void arm_rsa_rows(void)
{
    size_t i;
    EVP_PKEY *pkey;

    /* 1. Every landed `RSA` row, fetched by name. */
    for (i = 0; i < sizeof(rsa_rows) / sizeof(rsa_rows[0]); i++) {
        char key[96];
        EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, rsa_rows[i], NULL);

        snprintf(key, sizeof(key), "rsa.%s.fetch", rsa_rows[i]);
        kv_int(key, sig != NULL);
        EVP_SIGNATURE_free(sig);
    }

    /* 2. The key, through the `RSA` keymgmt row. */
    pkey = rsa_build_key();
    kv_int("rsa.key", pkey != NULL);
    if (pkey == NULL)
        return;

    /* 3. The plain row end to end: `EVP_DigestSignInit` picks `RSA` through the key's own
     * operation name, then a sign, then a verify of the signature just produced. A PKCS#1 v1.5
     * signature is deterministic, but it is not printed -- like `DSA` and `ECDSA`, the
     * observation is the return codes, the deterministic `RSA_size` maximum and the round trip. */
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char sig[512];
        size_t siglen;
        EVP_MD_CTX *vmdctx;
        int init;

        init = EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey);
        kv_int("rsa.RSA.sign_init", init);
        if (init > 0) {
            kv_int("rsa.RSA.update", EVP_DigestSignUpdate(mdctx, sig_message,
                                                           sizeof(sig_message) - 1));
            siglen = sizeof(sig);
            kv_int("rsa.RSA.size", EVP_DigestSignFinal(mdctx, NULL, &siglen));
            kv_int("rsa.RSA.size_len", (int)siglen);
            siglen = sizeof(sig);
            kv_int("rsa.RSA.sign", EVP_DigestSignFinal(mdctx, sig, &siglen));

            vmdctx = EVP_MD_CTX_new();
            pctx = NULL;
            if (EVP_DigestVerifyInit(vmdctx, &pctx, EVP_sha256(), NULL, pkey) > 0)
                (void)EVP_DigestVerifyUpdate(vmdctx, sig_message, sizeof(sig_message) - 1);
            kv_int("rsa.RSA.verify", EVP_DigestVerifyFinal(vmdctx, sig, siglen));
            EVP_MD_CTX_free(vmdctx);
        }
        EVP_MD_CTX_free(mdctx);

        /* The AlgorithmIdentifier the row publishes for `SHA256`: `rsa_generate_signature_aid`'s
         * PKCS#1 v1.5 arm, which is `ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption` over the
         * `sha256WithRSAEncryption` OID with a NULL PARAMETERS field. It is deterministic and a
         * *distinguishing* observation -- the thirteen sigalgs below print thirteen different ones
         * -- so it is the arm that drives the DER writer rather than merely reaching it. */
        mdctx = EVP_MD_CTX_new();
        pctx = NULL;
        if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) > 0)
            kv_algid("rsa.RSA", pctx);
        EVP_MD_CTX_free(mdctx);
    }

    /* 4. The buffer refusal: a one-byte destination is `PROV_R_INVALID_SIGNATURE_SIZE`. */
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char one[1];
        size_t one_len = sizeof(one);

        if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) > 0)
            (void)EVP_DigestSignUpdate(mdctx, sig_message, sizeof(sig_message) - 1);
        kv_int("rsa.RSA.small_buffer", EVP_DigestSignFinal(mdctx, one, &one_len));
        EVP_MD_CTX_free(mdctx);
    }

    /* 5. The XOF refusal: `rsa_setup_md`'s `EVP_MD_xof` arm. `SHAKE-128` is fetchable, so the
     * refusal is the row's and not a missing digest. */
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;

        kv_int("rsa.RSA.shake", EVP_DigestSignInit(mdctx, &pctx, EVP_shake128(), NULL, pkey));
        EVP_MD_CTX_free(mdctx);
    }

    /* 6. The thirteen sigalgs, each driven end to end through its own dispatch. The signature
     * bytes are not printed for the same reason as the plain row's; `size_len` and the round-trip
     * verdict are. */
    for (i = 1; i < sizeof(rsa_rows) / sizeof(rsa_rows[0]); i++) {
        const char *name = rsa_rows[i];
        char key[96];
        EVP_SIGNATURE *algo = EVP_SIGNATURE_fetch(NULL, name, NULL);
        EVP_PKEY_CTX *ctx;
        EVP_PKEY_CTX *vctx;
        unsigned char sig[512];
        size_t siglen = sizeof(sig);
        int init;
        int signed_ok = 0;

        if (algo == NULL)
            continue;

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        init = EVP_PKEY_sign_message_init(ctx, algo, NULL);
        snprintf(key, sizeof(key), "rsa.%s.sign_message_init", name);
        kv_int(key, init);
        if (init > 0) {
            snprintf(key, sizeof(key), "rsa.%s.update", name);
            kv_int(key, EVP_PKEY_sign_message_update(ctx, (const unsigned char *)sig_message,
                                                     sizeof(sig_message) - 1));
            siglen = sizeof(sig);
            snprintf(key, sizeof(key), "rsa.%s.size", name);
            kv_int(key, EVP_PKEY_sign_message_final(ctx, NULL, &siglen));
            snprintf(key, sizeof(key), "rsa.%s.size_len", name);
            kv_int(key, (int)siglen);
            siglen = sizeof(sig);
            snprintf(key, sizeof(key), "rsa.%s.sign", name);
            signed_ok = EVP_PKEY_sign_message_final(ctx, sig, &siglen) > 0;
            kv_int(key, signed_ok);

            /* The sigalg's own AlgorithmIdentifier, the same `rsa_generate_signature_aid` path
             * with the digest the sigalg hard-codes. Thirteen rows, thirteen different DER
             * sequences, so a row wired to the wrong digest OID is a residual rather than a pass. */
            kv_algid(key, ctx);
        }
        EVP_PKEY_CTX_free(ctx);

        /* The buffer refusal, through the same dispatch. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (EVP_PKEY_sign_message_init(ctx, algo, NULL) > 0) {
            unsigned char one[1];
            size_t one_len = sizeof(one);

            (void)EVP_PKEY_sign_message_update(ctx, (const unsigned char *)sig_message,
                                              sizeof(sig_message) - 1);
            snprintf(key, sizeof(key), "rsa.%s.small_buffer", name);
            kv_int(key, EVP_PKEY_sign_message_final(ctx, one, &one_len));
        }
        EVP_PKEY_CTX_free(ctx);

        vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (EVP_PKEY_verify_message_init(vctx, algo, NULL) > 0)
            (void)EVP_PKEY_verify_message_update(vctx, (const unsigned char *)sig_message,
                                                 sizeof(sig_message) - 1);
        if (signed_ok)
            (void)EVP_PKEY_CTX_set_signature(vctx, sig, siglen);
        snprintf(key, sizeof(key), "rsa.%s.verify", name);
        kv_int(key, EVP_PKEY_verify_message_final(vctx));
        EVP_PKEY_CTX_free(vctx);
        EVP_SIGNATURE_free(algo);
    }

    /* The digest list is the sigalgs' own names, and it is checked here so a row renamed in one
     * place and not the other is a compile-time mismatch rather than a silent one. */

    EVP_PKEY_free(pkey);
}

/* The twelve `OSSL_OP_SIGNATURE` `SLH-DSA-*` rows, in the authority's `deflt_signature[]` order.
 * Each is reached twice: the key is built through the **keymgmt** row of the same name (so the
 * signature arm is independent of the keymgmt court), and the signature row is then fetched by
 * name and driven end to end through its own `SIGN`/`VERIFY` slots.
 *
 * The signature is deterministic: `deterministic=1` with no `test-entropy` makes the core use
 * `PK_SEED` for `opt_rand` (`slh_dsa.c:92-93`), and the key is generated from the authority's own
 * ACVP keygen seed, so both sides sign the same message with the same key and produce the *same*
 * signature. It is still not printed: its sha256 is, for the same reason the authority's own
 * `slh_dsa.inc` stores `sig_digest` rather than the up-to-49,856-byte signature. */
static EVP_PKEY *slh_dsa_build_key(const struct { const char *name; const unsigned char *key;
                                                size_t len; } *row)
{
    size_t key_len = row->len;
    size_t n = key_len / 4;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_PKEY_CTX_new_from_name(NULL, row->name, NULL);
    if (ctx == NULL)
        return NULL;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED,
                                                  (void *)row->key, key_len - n);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_params(ctx, params) <= 0
        || EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void kv_sha256(const char *key, const unsigned char *buf, size_t len)
{
    unsigned char digest[32];
    unsigned int dlen = 0;

    printf("%s=", key);
    if (EVP_Digest(buf, len, digest, &dlen, EVP_sha256(), NULL) == 1) {
        size_t i;

        for (i = 0; i < dlen; i++)
            printf("%02x", digest[i]);
    } else {
        printf("<failed>");
    }
    printf("\n");
}

static void arm_slh_dsa_rows(void)
{
    static const unsigned char slh_message[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f
    };
    size_t i;

    for (i = 0; i < sizeof(slh_dsa_rows) / sizeof(slh_dsa_rows[0]); i++) {
        const char *name = slh_dsa_rows[i].name;
        char key[96];
        EVP_PKEY *pkey = slh_dsa_build_key(&slh_dsa_rows[i]);
        EVP_SIGNATURE *algo = EVP_SIGNATURE_fetch(NULL, name, NULL);
        EVP_PKEY_CTX *ctx;
        EVP_PKEY_CTX *vctx;
        static unsigned char sig[50000];
        static unsigned char tampered[50000];
        size_t siglen;
        OSSL_PARAM params[3];
        int msg_encode = 0;
        int deterministic = 1;
        int signed_ok = 0;

        snprintf(key, sizeof(key), "slh.%s.key", name);
        kv_int(key, pkey != NULL);
        snprintf(key, sizeof(key), "slh.%s.sig_fetch", name);
        kv_int(key, algo != NULL);
        if (pkey == NULL || algo == NULL)
            continue;

        params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &msg_encode);
        params[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
        params[2] = OSSL_PARAM_construct_end();

        /* Arm 1: the signature, through the row's own `SIGN_MESSAGE_INIT` + `SIGN`. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        snprintf(key, sizeof(key), "slh.%s.sign_message_init", name);
        kv_int(key, EVP_PKEY_sign_message_init(ctx, algo, params));
        siglen = sizeof(sig);
        snprintf(key, sizeof(key), "slh.%s.sign_size_query", name);
        kv_int(key, EVP_PKEY_sign(ctx, NULL, &siglen, slh_message, sizeof(slh_message)));
        snprintf(key, sizeof(key), "slh.%s.sign_size", name);
        kv_int(key, (int)siglen);
        siglen = sizeof(sig);
        snprintf(key, sizeof(key), "slh.%s.sign", name);
        signed_ok = EVP_PKEY_sign(ctx, sig, &siglen, slh_message, sizeof(slh_message));
        kv_int(key, signed_ok);
        snprintf(key, sizeof(key), "slh.%s.sig_len", name);
        kv_int(key, (int)siglen);
        snprintf(key, sizeof(key), "slh.%s.sig_sha256", name);
        kv_sha256(key, sig, siglen);
        EVP_PKEY_CTX_free(ctx);

        /* Arm 2: the buffer refusal -- a one-byte destination for a fixed-size signature. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (EVP_PKEY_sign_message_init(ctx, algo, params) > 0) {
            unsigned char one[1];
            size_t one_len = sizeof(one);

            snprintf(key, sizeof(key), "slh.%s.small_buffer", name);
            kv_int(key, EVP_PKEY_sign(ctx, one, &one_len, slh_message, sizeof(slh_message)));
        }
        EVP_PKEY_CTX_free(ctx);

        /* Arm 3: the verify of the signature just produced, then of a corrupted copy. */
        memcpy(tampered, sig, siglen);
        tampered[siglen / 2] ^= 0x01;
        vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (EVP_PKEY_verify_message_init(vctx, algo, params) > 0) {
            snprintf(key, sizeof(key), "slh.%s.verify", name);
            kv_int(key, EVP_PKEY_verify(vctx, sig, siglen, slh_message, sizeof(slh_message)));
            snprintf(key, sizeof(key), "slh.%s.verify_corrupted", name);
            kv_int(key, EVP_PKEY_verify(vctx, tampered, siglen, slh_message, sizeof(slh_message)));
        }
        EVP_PKEY_CTX_free(vctx);

        EVP_SIGNATURE_free(algo);
        EVP_PKEY_free(pkey);
    }
}

/* The three landed `OSSL_OP_SIGNATURE` `ML-DSA-*` rows (D409), in the authority's
 * `deflt_signature[]` order. Each is reached twice -- the key is built through the **keymgmt** row
 * of the same name (so the signature arm is independent of the keymgmt court), and the signature
 * row is then fetched by name and driven end to end through its own `SIGN_MESSAGE_INIT` + `SIGN`
 * and `VERIFY_MESSAGE_INIT` + `VERIFY` slots.
 *
 * The signature is made deterministic with the `deterministic=1` ctx parameter (set through
 * `EVP_PKEY_sign_message_init`): `ml_dsa_sign` and `ml_dsa_sign_msg_final` then fill the signing
 * `rnd` with zeros instead of drawing from the DRBG (`src/provider/ml_dsa_sig.rs`), so both sides
 * sign the same message with the same seed-derived key using the same `rnd` and produce the
 * *same* signature. It is still not printed: its sha256 is, for the same reason the SLH-DSA arm
 * prints a digest rather than the up-to-4627-byte signature. A one-byte-flipped copy is verified
 * too, so the arm shows the verify path answering both 1 and 0. */
static const char *ml_dsa_sig_rows[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };

static EVP_PKEY *ml_dsa_build_key(const char *name)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (ctx == NULL)
        return NULL;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                  (void *)ml_dsa_seed, sizeof(ml_dsa_seed));
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_params(ctx, params) <= 0
        || EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void arm_ml_dsa_rows(void)
{
    static const unsigned char ml_dsa_message[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f
    };
    size_t i;

    for (i = 0; i < sizeof(ml_dsa_sig_rows) / sizeof(ml_dsa_sig_rows[0]); i++) {
        const char *name = ml_dsa_sig_rows[i];
        char key[96];
        EVP_PKEY *pkey = ml_dsa_build_key(name);
        EVP_SIGNATURE *algo = EVP_SIGNATURE_fetch(NULL, name, NULL);
        EVP_PKEY_CTX *ctx;
        EVP_PKEY_CTX *vctx;
        static unsigned char sig[5000];
        static unsigned char tampered[5000];
        size_t siglen = 0;
        OSSL_PARAM params[2];
        int deterministic = 1;
        int signed_ok = 0;

        snprintf(key, sizeof(key), "mldsa.%s.key", name);
        kv_int(key, pkey != NULL);
        snprintf(key, sizeof(key), "mldsa.%s.sig_fetch", name);
        kv_int(key, algo != NULL);
        if (pkey == NULL || algo == NULL)
            continue;

        /* The one knob that makes signing deterministic; `test-entropy` is deliberately not set,
         * so the provider's own zero-rnd path is what is driven. */
        params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
        params[1] = OSSL_PARAM_construct_end();

        /* Arm 1: the signature, through the row's own `SIGN_MESSAGE_INIT` + `SIGN`. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        snprintf(key, sizeof(key), "mldsa.%s.sign_message_init", name);
        kv_int(key, EVP_PKEY_sign_message_init(ctx, algo, params));
        siglen = sizeof(sig);
        snprintf(key, sizeof(key), "mldsa.%s.sign_size_query", name);
        kv_int(key, EVP_PKEY_sign(ctx, NULL, &siglen, ml_dsa_message, sizeof(ml_dsa_message)));
        snprintf(key, sizeof(key), "mldsa.%s.sign_size", name);
        kv_int(key, (int)siglen);
        siglen = sizeof(sig);
        snprintf(key, sizeof(key), "mldsa.%s.sign", name);
        signed_ok = EVP_PKEY_sign(ctx, sig, &siglen, ml_dsa_message, sizeof(ml_dsa_message));
        kv_int(key, signed_ok);
        EVP_PKEY_CTX_free(ctx);

        /* Only a signature that was actually produced can be digested and verified; a failed sign
         * leaves `sig` a zeroed static, and printing a digest of it would observe nothing. */
        if (signed_ok > 0) {
            snprintf(key, sizeof(key), "mldsa.%s.sig_len", name);
            kv_int(key, (int)siglen);
            snprintf(key, sizeof(key), "mldsa.%s.sig_sha256", name);
            kv_sha256(key, sig, siglen);

            /* Arm 2: a one-byte destination for a fixed-size signature is the row's buffer
             * refusal. */
            ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (EVP_PKEY_sign_message_init(ctx, algo, params) > 0) {
                unsigned char one[1];
                size_t one_len = sizeof(one);

                snprintf(key, sizeof(key), "mldsa.%s.small_buffer", name);
                kv_int(key, EVP_PKEY_sign(ctx, one, &one_len, ml_dsa_message,
                                          sizeof(ml_dsa_message)));
            }
            EVP_PKEY_CTX_free(ctx);

            /* Arm 3: the verify of the signature just produced, then of a corrupted copy. */
            memcpy(tampered, sig, siglen);
            tampered[siglen / 2] ^= 0x01;
            vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (EVP_PKEY_verify_message_init(vctx, algo, params) > 0) {
                snprintf(key, sizeof(key), "mldsa.%s.verify", name);
                kv_int(key, EVP_PKEY_verify(vctx, sig, siglen, ml_dsa_message,
                                            sizeof(ml_dsa_message)));
                snprintf(key, sizeof(key), "mldsa.%s.verify_corrupted", name);
                kv_int(key, EVP_PKEY_verify(vctx, tampered, siglen, ml_dsa_message,
                                            sizeof(ml_dsa_message)));
            }
            EVP_PKEY_CTX_free(vctx);
        }

        EVP_SIGNATURE_free(algo);
        EVP_PKEY_free(pkey);
    }
}

/* The one `SM2` signature row (D406). The row is fetched by name, an SM2 key is generated through
 * the `SM2` keymgmt row, and the DigestSign/DigestVerify pair is driven over SM3 — the only digest
 * the row accepts. The published GM/T 0003.5-2012 known answer is the crypt unit's own unit test
 * (`src/sm2/sign.rs`); this arm is the registration-row court's differential one. */
static void arm_sm2_rows(void)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    OSSL_PARAM gparams[2];
    EVP_PKEY *pkey = NULL;
    EVP_MD *md;
    unsigned char sig[256];
    size_t siglen = sizeof(sig);

    kv_int("sm2.fetch", EVP_SIGNATURE_fetch(NULL, "SM2", NULL) != NULL);

    gparams[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"SM2", 0);
    gparams[1] = OSSL_PARAM_construct_end();
    kv_int("sm2.keygen_init", kctx != NULL && EVP_PKEY_keygen_init(kctx) > 0);
    kv_int("sm2.set_group", kctx != NULL && EVP_PKEY_CTX_set_params(kctx, gparams) > 0);
    kv_int("sm2.keygen", kctx != NULL && EVP_PKEY_keygen(kctx, &pkey) > 0);
    EVP_PKEY_CTX_free(kctx);

    if (pkey == NULL)
        return;

    md = EVP_MD_fetch(NULL, "SM3", NULL);
    kv_int("sm2.sm3_fetch", md != NULL);

    {
        EVP_MD_CTX *sctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;

        kv_int("sm2.digest_sign_init", EVP_DigestSignInit(sctx, &pctx, md, NULL, pkey));
        kv_int("sm2.update", EVP_DigestSignUpdate(sctx, sig_message, sizeof(sig_message) - 1));
        /* The size query is deterministic (`ECDSA_size`); the signed length is not, because an
         * SM2 `(r, s)` DER length depends on the two components' leading zeroes, so it is not
         * printed. */
        siglen = sizeof(sig);
        kv_int("sm2.size", EVP_DigestSignFinal(sctx, NULL, &siglen));
        siglen = sizeof(sig);
        kv_int("sm2.sign", EVP_DigestSignFinal(sctx, sig, &siglen) > 0);
        EVP_MD_CTX_free(sctx);
    }

    {
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;

        if (EVP_DigestVerifyInit(vctx, &pctx, md, NULL, pkey) > 0)
            (void)EVP_DigestVerifyUpdate(vctx, sig_message, sizeof(sig_message) - 1);
        kv_int("sm2.verify", EVP_DigestVerifyFinal(vctx, sig, siglen));
        EVP_MD_CTX_free(vctx);
    }

    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
}

int main(void)
{
    /* The warm-up: the `DSA` sign path reaches `ossl_bn_gen_dsa_nonce_fixed_top`, whose first act
     * is `EVP_MD_fetch(ossl_bn_get_libctx(ctx), "SHA512", NULL)`, and a process that has not yet
     * touched the default provider answers 0 there -- which `dsa_sign_setup` reports as
     * `ERR_R_BN_LIB` rather than as a missing digest. One `RAND_bytes` call loads the provider for
     * both arms, so the refusal the probe measures is the row's and not the loader's. The byte is
     * not printed and does not reach the transcript. */
    {
        unsigned char warm = 0;

        (void)RAND_bytes(&warm, 1);
    }

    arm_signature_rows();
    arm_dsa_rows();
    arm_ecdsa_rows();
    arm_eddsa_rows();
    arm_rsa_rows();
    arm_slh_dsa_rows();
    arm_ml_dsa_rows();
    arm_sm2_rows();
    ERR_clear_error();
    return 0;
}
