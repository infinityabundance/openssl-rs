/*
 * RT-KEYMGMT -- Phase 8's key-management and key-exchange registration court.
 *
 * This court exists because the registration rows the earlier passes landed were **named** but
 * not **driven**. `provider_court_coverage.py` (D245) requires every row the census calls
 * `implemented` to be named by a probe of a differential court, and `rt_digest_probe.c` names
 * `TLS1-PRF`, `HKDF` and `SCRYPT` because those three are also `OSSL_OP_KDF` rows it fetches by
 * name. That satisfies the coverage join -- and says nothing whatever about the `OSSL_OP_KEYMGMT`
 * and `OSSL_OP_KEYEXCH` rows, which are *different rows under different operations*. This probe
 * is the arm that drives them: it fetches each keymgmt row by type name, builds a key through it,
 * and reaches the keyexch row through the key it built.
 *
 * ## Why the arms are context-construction and not key values
 *
 * Everything below is a return code, a size, or a boolean comparison between two values the probe
 * itself computed -- never a generated key, never a derived secret. A DH key generation or a DH
 * agreement is deterministic given the parameters, but a **generated** private key is not, and a
 * probe that printed one would differ between two runs of the same side. Where this court wants a
 * concrete key it imports one the probe computed in Python from the published FFDHE-2048 prime in
 * `src/bn/dh_data.rs` -- a public constant, not a secret -- so both sides work on identical input.
 *
 * ## What each arm observes
 *
 *   1. **The keymgmt fetch.** `EVP_PKEY_CTX_new_from_name(NULL, <name>, NULL)` for each of the
 *      five landed `OSSL_OP_KEYMGMT` rows (`DH`, `DHX`, `TLS1-PRF`, `HKDF`, `SCRYPT`), plus a
 *      name no provider holds. Before D386 the first two answered NULL; before D387 `DH` did.
 *   2. **The key build, through the row.** `EVP_PKEY_fromdata` imports FFDHE-2048 parameters into
 *      the type `DH` names, and the resulting `EVP_PKEY` is asked for `EVP_PKEY_get_bits`,
 *      `EVP_PKEY_get_size`, `EVP_PKEY_get_security_bits` and its `id`. Those four are the
 *      keymgmt object's `get_params` and its import path, observed through a public key.
 *   3. **The parameter refusal.** A `fromdata` with no group at all, and the same with an
 *      unknown group name -- the keymgmt's own refusals, observed as `0`.
 *   4. **The keyexch fetch and init.** `EVP_PKEY_CTX_new_from_name(NULL, <name>, NULL)` and
 *      `EVP_PKEY_derive_init` for each landed `OSSL_OP_KEYEXCH` row, and the derive that
 *      follows for the KDF rows (whose `derive` needs no key material, only a `key` parameter the
 *      probe does not set, so its answer is the row's own missing-parameter refusal).
 *
 * ## What this court deliberately does not observe
 *
 *   * **Any generated key or derived secret.** See above: two runs of one side must agree, and a
 *     generated private key would not.
 *   * **`EVP_PKEY_get_id`.** It is the `EVP_PKEY` object's **legacy type assignment**
 *     (`evp_pkey_set_type_by_keymgmt` on the authority), not the keymgmt row's contract, and the
 *     crate does not assign a legacy type to a provider-built key yet: measured, the authority
 *     answers `EVP_PKEY_DH` (28) and the crate answers `-1`. That is a Phase 7 `EVP_PKEY` subject
 *     and is named here rather than courted, so this court does not carry a residual about a unit
 *     it is not the evidence for.
 *   * **`EVP_PKEY_derive` over the `DH` row.** It needs a peer public key and a private scalar;
 *     the `DH` row's own agreement is exercised by `src/dh/key.rs`'s unit test over the published
 *     RFC 7919 group, and running it here would print a value the two sides must share but that
 *     this court has no independent way to check.
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

/* The five landed OSSL_OP_KEYMGMT rows, in the authority's deflt_keymgmt[] order. */
static const char *kmgmt_rows[] = { "DH", "DHX", "TLS1-PRF", "HKDF", "SCRYPT" };

/* The landed OSSL_OP_KEYEXCH rows. The KDF trio is fetched by the same names the keymgmt rows
 * answer; `DH` resolves its keyexch row through the `DH` keymgmt row's operation name. */
static const char *keyexch_rows[] = { "DH", "TLS1-PRF", "HKDF", "SCRYPT" };

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

int main(void)
{
    arm_keymgmt_fetch();
    arm_keyexch_fetch();
    arm_dh_import();
    ERR_clear_error();
    return 0;
}
