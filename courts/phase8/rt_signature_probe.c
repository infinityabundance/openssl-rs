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
            (void)EVP_PKEY_verify_message_update(vctx, sig_message, sizeof(sig_message) - 1);
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
    ERR_clear_error();
    return 0;
}
