/*
 * RT-KEYMGMT -- Phase 8's key-management, key-exchange and KEM registration court.
 *
 * This court exists because the registration rows the earlier passes landed were **named** but
 * not **driven**. `provider_court_coverage.py` (D245) requires every row the census calls
 * `implemented` to be named by a probe of a differential court, and `rt_digest_probe.c` names
 * `TLS1-PRF`, `HKDF` and `SCRYPT` because those three are also `OSSL_OP_KDF` rows it fetches by
 * name. That satisfies the coverage join -- and says nothing whatever about the `OSSL_OP_KEYMGMT`,
 * `OSSL_OP_KEYEXCH` and `OSSL_OP_KEM` rows, which are *different rows under different
 * operations*. This probe is the arm that drives them: it fetches each keymgmt row by type name,
 * builds a key through it, and reaches the exchange and KEM rows through the key it built.
 *
 * ## Why the arms are context-construction and not key values
 *
 * Everything below is a return code, a size, or a boolean comparison between two values the probe
 * itself computed -- never a generated key, never a derived secret. A DH key generation or a DH
 * agreement is deterministic given the parameters, but a **generated** private key is not, and a
 * probe that printed one would differ between two runs of the same side. Where this court wants a
 * concrete key it imports one the probe carries as a public constant -- the published FFDHE-2048
 * prime (in `src/bn/dh_data.rs`) for `DH`, and the published RFC 7748/8032 base points and test
 * public keys for the four ECX types -- so both sides work on identical input.
 *
 * ## What each arm observes
 *
 *   1. **The keymgmt fetch.** `EVP_PKEY_CTX_new_from_name(NULL, <name>, NULL)` for each of the
 *      eighteen landed `OSSL_OP_KEYMGMT` rows (`DH`, `DHX`, `DSA`, `RSA`, `RSA-PSS`, `EC`, the
 *      four ECX types, the KDF trio, the four legacy MAC types and `SM2`), plus a name no
 *      provider holds. Before D386 the first two answered NULL; before D387 `DH` did; before
 *      D388 the four ECX names did; before D389 the four MAC names did; before D390 `EC` and
 *      `SM2` did; before D391 `RSA`, `RSA-PSS` and `DSA` did.
 *   2. **The key build, through the row.** `EVP_PKEY_fromdata` imports FFDHE-2048 parameters into
 *      the type `DH` names, and the resulting `EVP_PKEY` is asked for `EVP_PKEY_get_bits`,
 *      `EVP_PKEY_get_size`, `EVP_PKEY_get_security_bits`. Those are the keymgmt object's
 *      `get_params` and its import path, observed through a public key.
 *   3. **The parameter refusal.** A `fromdata` with no group at all, and the same with an
 *      unknown group name -- the keymgmt's own refusals, observed as `0`.
 *   4. **The ECX import and its four object accessors.** Each of `X25519`, `X448`, `ED25519` and
 *      `ED448` imports a **fixed public key** (RFC 7748's base points, RFC 8032's first test
 *      vectors) through its own keymgmt row, and the object answers `bits`/`size`/`security-bits`
 *      (`253`/`32`/`128`, `448`/`56`/`224`, `256`/`64`/`128`, `456`/`114`/`224`). A wrong-length
 *      public key is a fifth observation per type, and the two refusals are the keymgmt's own.
 *   5. **The keyexch fetch and init.** `EVP_PKEY_CTX_new_from_name(NULL, <name>, NULL)` and
 *      `EVP_PKEY_derive_init` for each landed `OSSL_OP_KEYEXCH` row, and -- for the two ECX rows,
 *      which need a key -- `EVP_PKEY_CTX_new_from_pkey` over the key parsed in arm 4 and a second
 *      `derive_init` through *that* context.
 *   6. **The KEM fetch and init.** The same two ECX keys, under `OSSL_OP_KEM`: a context from the
 *      parsed key, then `EVP_PKEY_encapsulate_init` and `EVP_PKEY_decapsulate_init`. The first
 *      succeeds on a public-only key and the second *refuses* it (`ecx_key_check` wants a private
 *      key), which is the row's own answer rather than a missing arm.
 *   7. **The four legacy-MAC imports.** `HMAC`, `SIPHASH`, `POLY1305` and `CMAC` each import a
 *      fixed 16-byte private key through their own keymgmt row, and the no-key refusal is the
 *      fifth observation per type. `CMAC`'s import is the one that resolves a cipher through
 *      `ossl_prov_cipher_load_from_params`, so it is observed twice more: once with a cipher the
 *      provider holds and once with a name it does not, which is `mac_key_fromdata`'s own
 *      `ERR_R_PASSED_INVALID_ARGUMENT` site (`mac_legacy_kmgmt.c:212`).
 *   8. **The `EC` and `SM2` imports and the cofactor of the two rows' own check.** `EC` imports
 *      the published NIST P-256 group by name and reads `bits`/`size`/`security-bits`; `SM2`
 *      imports its own group the same way. What the two rows refuse is the interesting part and
 *      it is `common_check_sm2`'s own answer rather than a missing arm: **`EC` refuses the SM2
 *      curve and `SM2` refuses P-256**, because each wants `sm2_wanted` to agree with the curve's
 *      `NID_sm2`. `EC`'s unknown group is a third refusal. The `EC` key also reaches the `ECDH`
 *      keyexch row through its own operation name -- `EVP_PKEY_CTX_new_from_pkey` over the imported
 *      key and `EVP_PKEY_derive_init`, which is `ec_query_operation_name`'s `ECDH` answer.
 *   9. **The `RSA`, `RSA-PSS` and `DSA` imports.** Each imports a **fixed public** parameter set
 *      through its own row -- a small public modulus and the F4 exponent for the two RSA rows, a
 *      small public `p`/`q`/`g` triple for `DSA` -- and reads `bits`/`size`/`security-bits`, then
 *      rebuilds a context from the imported key with `EVP_PKEY_CTX_new_from_pkey`. The empty
 *      `fromdata` is the row's own refusal. The small values are the shape `rt_rsa_probe.c`
 *      already uses (`n = 3233`, `e = 65537`); nothing here is generated.
 *
 * ## What this court deliberately does not observe
 *
 *   * **Any generated key, derived secret or encapsulated secret.** See above: two runs of one
 *     side must agree, and a generated private key or a random seed would not.
 *   * **`EVP_PKEY_get_id`.** It is the `EVP_PKEY` object's **legacy type assignment**
 *     (`evp_pkey_set_type_by_keymgmt` on the authority), not the keymgmt row's contract, and the
 *     crate does not assign a legacy type to a provider-built key yet: measured, the authority
 *     answers `EVP_PKEY_DH` (28) and the crate answers `-1`. That is a Phase 7 `EVP_PKEY` subject
 *     and is named here rather than courted, so this court does not carry a residual about a unit
 *     it is not the evidence for.
 *   * **`EVP_PKEY_derive` over the `DH` or ECX rows.** It needs a peer public key and a private
 *     scalar; the rows' own agreements are exercised by unit tests over the published groups and
 *     the RFC 7748 vectors, and running one here would print a value the two sides must share but
 *     that this court has no independent way to check.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>

static void kv_int(const char *key, int value)
{
    printf("%s=%d\n", key, value);
}

/* The eight landed OSSL_OP_KEYMGMT rows this probe fetches, plus the eight it does not: the list is
 * the authority's deflt_keymgmt[] order, restricted to the rows the crate publishes. */
static const char *kmgmt_rows[] = { "DH", "DHX", "DSA", "RSA", "RSA-PSS", "EC", "X25519", "X448",
                                    "ED25519", "ED448", "TLS1-PRF", "HKDF", "SCRYPT", "HMAC",
                                    "SIPHASH", "POLY1305", "CMAC", "SM2" };

/* The landed OSSL_OP_KEYEXCH rows. The KDF trio is fetched by the same names the keymgmt rows
 * answer; `DH` and the two ECX rows are their own keymgmt names, so a context with no key still
 * resolves. `ECDH` is a *keyexch-only* row: `EVP_PKEY_CTX_new_from_name` looks up `OSSL_OP_KEYMGMT`
 * and the authority holds no `ECDH` keymgmt, so its context fetches as NULL and that 0 is the
 * authority's own answer, kept as the differential observation it is. The row is driven by `EC`
 * instead -- `arm_ec_import`'s `EVP_PKEY_CTX_new_from_pkey` over an imported `EC` key and
 * `EVP_PKEY_derive_init`, which is `ec_query_operation_name`'s `ECDH` answer for `OSSL_OP_KEYEXCH`. */
static const char *keyexch_rows[] = { "DH", "ECDH", "X25519", "X448", "TLS1-PRF", "HKDF", "SCRYPT" };

/* The two landed OSSL_OP_KEM rows, which are also keymgmt and keyexch names. */
static const char *kem_rows[] = { "X25519", "X448" };

/* The four landed legacy-MAC keymgmt rows. The private key below is a fixed public constant, not
 * a secret: it is an input the two sides must agree on, not a generated key. */
static const char *mac_rows[] = { "HMAC", "SIPHASH", "POLY1305", "CMAC" };
static const unsigned char mac_priv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static void arm_keymgmt_fetch(void)
{
    size_t i;

    for (i = 0; i < sizeof(kmgmt_rows) / sizeof(kmgmt_rows[0]); i++) {
        char key[64];
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, kmgmt_rows[i], NULL);

        snprintf(key, sizeof(key), "kmgmt.%s.ctx", kmgmt_rows[i]);
        kv_int(key, ctx != NULL);
        EVP_PKEY_CTX_free(ctx);
    }

    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "NO-SUCH-KEYTYPE", NULL);

        kv_int("kmgmt.absent.ctx", ctx != NULL);
        EVP_PKEY_CTX_free(ctx);
    }
}

static void arm_keyexch_fetch(void)
{
    size_t i;

    for (i = 0; i < sizeof(keyexch_rows) / sizeof(keyexch_rows[0]); i++) {
        char key[64];
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, keyexch_rows[i], NULL);

        snprintf(key, sizeof(key), "keyexch.%s.ctx", keyexch_rows[i]);
        kv_int(key, ctx != NULL);
        if (ctx != NULL) {
            snprintf(key, sizeof(key), "keyexch.%s.derive_init", keyexch_rows[i]);
            kv_int(key, EVP_PKEY_derive_init(ctx));
        }
        EVP_PKEY_CTX_free(ctx);
    }

    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "NO-SUCH-KEYTYPE", NULL);

        kv_int("keyexch.absent.ctx", ctx != NULL);
        EVP_PKEY_CTX_free(ctx);
    }
}

/* Import FFDHE-2048 parameters into a `DH` key and read the four object accessors back. */
static void arm_dh_import(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    OSSL_PARAM params[2];
    EVP_PKEY *pkey = NULL;

    kv_int("dh.fromdata_init", EVP_PKEY_fromdata_init(ctx));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)"ffdhe2048", 0);
    params[1] = OSSL_PARAM_construct_end();
    kv_int("dh.fromdata.group", EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
    if (pkey != NULL) {
        kv_int("dh.bits", EVP_PKEY_get_bits(pkey));
        kv_int("dh.size", EVP_PKEY_get_size(pkey));
        kv_int("dh.security_bits", EVP_PKEY_get_security_bits(pkey));
    }
    EVP_PKEY_free(pkey);

    /* The two refusals: no group at all, and a group the provider does not hold. */
    params[0] = OSSL_PARAM_construct_end();
    pkey = NULL;
    kv_int("dh.fromdata.empty",
           EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
    EVP_PKEY_free(pkey);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)"nosuchgroup", 0);
    pkey = NULL;
    kv_int("dh.fromdata.unknown_group",
           EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
    EVP_PKEY_free(pkey);

    EVP_PKEY_CTX_free(ctx);
}

/* The published ECX public constants. X25519 and X448 are RFC 7748's base points (u = 9 and
 * u = 5); ED25519 and ED448 are RFC 8032 section 7.1/7.4 test vector 1's public keys. They are
 * public inputs, not secrets. */
static const unsigned char x25519_pub[32] = {
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char x448_pub[56] = {
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char ed25519_pub[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};
static const unsigned char ed448_pub[57] = {
    0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd, 0x2c, 0xe7, 0x87, 0xec, 0x61, 0x6a, 0xd4,
    0x6a, 0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f, 0x8a, 0x0e, 0xa7, 0x5d, 0x80, 0xe9,
    0x67, 0x78, 0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06, 0x1b, 0xd6, 0x78, 0x3d, 0xf1,
    0xe5, 0x0f, 0x6c, 0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61, 0x80
};

struct ecx_row {
    const char *name;
    const unsigned char *pub;
    size_t publen;
    int derives; /* whether an OSSL_OP_KEYEXCH row of this name exists */
    int kems;    /* whether an OSSL_OP_KEM row of this name exists */
};

static const struct ecx_row ecx_rows[] = {
    { "X25519", x25519_pub, sizeof(x25519_pub), 1, 1 },
    { "X448", x448_pub, sizeof(x448_pub), 1, 1 },
    { "ED25519", ed25519_pub, sizeof(ed25519_pub), 0, 0 },
    { "ED448", ed448_pub, sizeof(ed448_pub), 0, 0 }
};

/* Import each ECX row's fixed public key through its own keymgmt row, read the three object
 * accessors, then reach the keyexch and KEM rows through a context built from *that* key. */
static void arm_ecx_import(void)
{
    size_t i;

    for (i = 0; i < sizeof(ecx_rows) / sizeof(ecx_rows[0]); i++) {
        const struct ecx_row *r = &ecx_rows[i];
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, r->name, NULL);
        OSSL_PARAM params[2];
        EVP_PKEY *pkey = NULL;
        EVP_PKEY_CTX *kctx;
        char key[64];

        snprintf(key, sizeof(key), "ecx.%s.fromdata_init", r->name);
        kv_int(key, EVP_PKEY_fromdata_init(ctx));
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                      (void *)r->pub, r->publen);
        params[1] = OSSL_PARAM_construct_end();
        snprintf(key, sizeof(key), "ecx.%s.fromdata", r->name);
        kv_int(key, EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params));

        if (pkey != NULL) {
            snprintf(key, sizeof(key), "ecx.%s.bits", r->name);
            kv_int(key, EVP_PKEY_get_bits(pkey));
            snprintf(key, sizeof(key), "ecx.%s.size", r->name);
            kv_int(key, EVP_PKEY_get_size(pkey));
            snprintf(key, sizeof(key), "ecx.%s.security_bits", r->name);
            kv_int(key, EVP_PKEY_get_security_bits(pkey));

            kctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (r->derives) {
                snprintf(key, sizeof(key), "ecx.%s.key.derive_init", r->name);
                kv_int(key, EVP_PKEY_derive_init(kctx));
            }
            if (r->kems) {
                snprintf(key, sizeof(key), "ecx.%s.key.encapsulate_init", r->name);
                kv_int(key, EVP_PKEY_encapsulate_init(kctx, NULL));
                snprintf(key, sizeof(key), "ecx.%s.key.decapsulate_init", r->name);
                kv_int(key, EVP_PKEY_decapsulate_init(kctx, NULL));
            }
            EVP_PKEY_CTX_free(kctx);
        }
        EVP_PKEY_free(pkey);

        /* A public key of the wrong length is a second refusal, and it is the keymgmt's own. */
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                      (void *)r->pub, r->publen - 1);
        pkey = NULL;
        snprintf(key, sizeof(key), "ecx.%s.fromdata.short", r->name);
        kv_int(key, EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params));
        EVP_PKEY_free(pkey);

        EVP_PKEY_CTX_free(ctx);
    }
}

/* The two KEM rows under their own operation: a context with no key at all, which every provider
 * refuses identically, so the fetch and the refusal are both observable. */
static void arm_kem_fetch(void)
{
    size_t i;

    for (i = 0; i < sizeof(kem_rows) / sizeof(kem_rows[0]); i++) {
        char key[64];
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, kem_rows[i], NULL);

        snprintf(key, sizeof(key), "kem.%s.ctx", kem_rows[i]);
        kv_int(key, ctx != NULL);
        if (ctx != NULL) {
            snprintf(key, sizeof(key), "kem.%s.encapsulate_init_nokey", kem_rows[i]);
            kv_int(key, EVP_PKEY_encapsulate_init(ctx, NULL));
        }
        EVP_PKEY_CTX_free(ctx);
    }

    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "NO-SUCH-KEYTYPE", NULL);

        kv_int("kem.absent.ctx", ctx != NULL);
        EVP_PKEY_CTX_free(ctx);
    }
}

/* The two landed EC keymgmt rows. `EC`'s curve is the published NIST P-256 group; `SM2`'s is the
 * SM2 group its own `gen_init` defaults to. Both are named groups the provider holds, not
 * generated keys. */
/* The two landed EC keymgmt rows. `EC`'s curve is the published NIST P-256 group; `SM2`'s is the
 * SM2 group its own `gen_init` defaults to. Both are named groups the provider holds, not
 * generated keys. */
static void arm_ec_import(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    OSSL_PARAM params[2];
    EVP_PKEY *pkey = NULL;

    kv_int("ec.fromdata_init", EVP_PKEY_fromdata_init(ctx));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)"prime256v1", 0);
    params[1] = OSSL_PARAM_construct_end();
    kv_int("ec.fromdata", EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
    if (pkey != NULL) {
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);

        kv_int("ec.bits", EVP_PKEY_get_bits(pkey));
        kv_int("ec.size", EVP_PKEY_get_size(pkey));
        kv_int("ec.security_bits", EVP_PKEY_get_security_bits(pkey));
        /* The `ECDH` keyexch row, reached through the `EC` key's own operation name. */
        kv_int("ec.key.derive_init", EVP_PKEY_derive_init(kctx));
        EVP_PKEY_CTX_free(kctx);
    }
    EVP_PKEY_free(pkey);

    /* The EC row refuses the SM2 curve: `common_check_sm2` wants the two to agree. */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"SM2", 0);
    pkey = NULL;
    kv_int("ec.fromdata.sm2_curve",
           EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
    EVP_PKEY_free(pkey);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)"nosuchgroup", 0);
    pkey = NULL;
    kv_int("ec.fromdata.unknown_group",
           EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    kv_int("sm2.fromdata_init", EVP_PKEY_fromdata_init(ctx));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"SM2", 0);
    params[1] = OSSL_PARAM_construct_end();
    pkey = NULL;
    kv_int("sm2.fromdata", EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
    if (pkey != NULL) {
        kv_int("sm2.bits", EVP_PKEY_get_bits(pkey));
        kv_int("sm2.size", EVP_PKEY_get_size(pkey));
        kv_int("sm2.security_bits", EVP_PKEY_get_security_bits(pkey));
    }
    EVP_PKEY_free(pkey);

    /* And the SM2 row refuses a curve that is not SM2's. */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)"prime256v1", 0);
    pkey = NULL;
    kv_int("sm2.fromdata.ec_curve",
           EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

/* The three landed `RSA`, `RSA-PSS` and `DSA` keymgmt rows. The public parameters below are fixed
 * probe-side constants -- a public modulus and the F4 exponent, and a public DSA domain-parameter
 * triple -- never a generated key, so two runs of one side agree. */
static const unsigned char rsa_probe_n[2] = { 0x0c, 0xa1 };             /* 3233 = 61 * 53 */
static const unsigned char rsa_probe_e[3] = { 0x01, 0x00, 0x01 };       /* 65537 */
static const unsigned char dsa_probe_p[2] = { 0x0c, 0xa1 };             /* 3233 */
static const unsigned char dsa_probe_q[1] = { 0x35 };                   /* 53 */
static const unsigned char dsa_probe_g[1] = { 0x02 };                   /* 2 */

static void arm_rsa_dsa_import(void)
{
    static const char *rows[] = { "RSA", "RSA-PSS", "DSA" };
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        const char *name = rows[i];
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
        OSSL_PARAM params[4];
        EVP_PKEY *pkey = NULL;
        char key[64];

        snprintf(key, sizeof(key), "rd.%s.fromdata_init", name);
        kv_int(key, EVP_PKEY_fromdata_init(ctx));

        if (strcmp(name, "DSA") == 0) {
            params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, (unsigned char *)dsa_probe_p,
                                                sizeof(dsa_probe_p));
            params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, (unsigned char *)dsa_probe_q,
                                                sizeof(dsa_probe_q));
            params[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, (unsigned char *)dsa_probe_g,
                                                sizeof(dsa_probe_g));
            params[3] = OSSL_PARAM_construct_end();
            snprintf(key, sizeof(key), "rd.%s.fromdata", name);
            kv_int(key, EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
        } else {
            params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, (unsigned char *)rsa_probe_n,
                                                sizeof(rsa_probe_n));
            params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, (unsigned char *)rsa_probe_e,
                                                sizeof(rsa_probe_e));
            params[2] = OSSL_PARAM_construct_end();
            snprintf(key, sizeof(key), "rd.%s.fromdata", name);
            kv_int(key, EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params));
        }

        if (pkey != NULL) {
            EVP_PKEY_CTX *kctx;

            snprintf(key, sizeof(key), "rd.%s.bits", name);
            kv_int(key, EVP_PKEY_get_bits(pkey));
            snprintf(key, sizeof(key), "rd.%s.size", name);
            kv_int(key, EVP_PKEY_get_size(pkey));
            snprintf(key, sizeof(key), "rd.%s.security_bits", name);
            kv_int(key, EVP_PKEY_get_security_bits(pkey));

            /* A context built from the imported key: the row's own keymgmt object again, through
             * the dispatch table rather than the name. */
            kctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            snprintf(key, sizeof(key), "rd.%s.key.ctx", name);
            kv_int(key, kctx != NULL);
            EVP_PKEY_CTX_free(kctx);
        }
        EVP_PKEY_free(pkey);

        /* No parameters at all: the row's own refusal. */
        params[0] = OSSL_PARAM_construct_end();
        pkey = NULL;
        snprintf(key, sizeof(key), "rd.%s.fromdata.empty", name);
        kv_int(key, EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params));
        EVP_PKEY_free(pkey);

        EVP_PKEY_CTX_free(ctx);
    }
}

/* The four legacy-MAC rows under `OSSL_OP_KEYMGMT`: a fixed private key imported through each
 * row, the no-key refusal, and -- for `CMAC` -- the cipher `mac_key_fromdata` resolves through
 * `ossl_prov_cipher_load_from_params`, once with a cipher the provider holds and once with one it
 * does not. */
static void arm_mac_import(void)
{
    size_t i;

    for (i = 0; i < sizeof(mac_rows) / sizeof(mac_rows[0]); i++) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, mac_rows[i], NULL);
        OSSL_PARAM params[3];
        EVP_PKEY *pkey = NULL;
        char key[64];

        snprintf(key, sizeof(key), "mac.%s.fromdata_init", mac_rows[i]);
        kv_int(key, EVP_PKEY_fromdata_init(ctx));

        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                      (void *)mac_priv, sizeof(mac_priv));
        params[1] = OSSL_PARAM_construct_end();
        snprintf(key, sizeof(key), "mac.%s.fromdata", mac_rows[i]);
        kv_int(key, EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params));
        EVP_PKEY_free(pkey);

        /* No private key at all: the row's own refusal. */
        params[0] = OSSL_PARAM_construct_end();
        pkey = NULL;
        snprintf(key, sizeof(key), "mac.%s.fromdata.empty", mac_rows[i]);
        kv_int(key, EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params));
        EVP_PKEY_free(pkey);

        /* CMAC is the row that resolves a cipher out of the same parameter array. */
        if (strcmp(mac_rows[i], "CMAC") == 0) {
            params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                          (void *)mac_priv, sizeof(mac_priv));
            params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER,
                                                         (char *)"AES-128-CBC", 0);
            params[2] = OSSL_PARAM_construct_end();
            pkey = NULL;
            kv_int("mac.CMAC.fromdata.cipher",
                   EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params));
            EVP_PKEY_free(pkey);

            params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER,
                                                         (char *)"NO-SUCH-CIPHER", 0);
            pkey = NULL;
            kv_int("mac.CMAC.fromdata.bad_cipher",
                   EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params));
            EVP_PKEY_free(pkey);
        }
        EVP_PKEY_CTX_free(ctx);
    }
}

int main(void)
{
    arm_keymgmt_fetch();
    arm_keyexch_fetch();
    arm_dh_import();
    arm_ecx_import();
    arm_ec_import();
    arm_rsa_dsa_import();
    arm_mac_import();
    arm_kem_fetch();
    ERR_clear_error();
    return 0;
}
