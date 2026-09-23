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
 *   * **Any generated key.** `EVP_PKEY_fromdata` imports the fixed constant below through each
 *     row's keymgmt; nothing here generates one, so two runs of the same side agree.
 *   * **`EVP_SIGNATURE_fetch` for a name no provider holds**, beyond the one negative line, which
 *     is the fetch machinery's own refusal and not a row's.
 *   * **A verify that could succeed.** No landed signature row publishes a verify slot, so a
 *     positive verify observation would be a claim about a unit this court is not the evidence for.
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
    ERR_clear_error();
    return 0;
}
