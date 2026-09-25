/*
 * RT-CODEC -- Phase 10.1's provider codec court, over the eleven text-encoder rows 10.1 lands.
 *
 * This is the first behavioural court of the key-format stratum. Until it, the only probe Phase 10
 * had (`rt_coverage_ref_probe.c`) took the *address* of the eighty-seven inherited exports and
 * claimed nothing about any of them; every one of this stratum's own rows was unimplemented. This
 * probe drives the rows `providers/implementations/encode_decode/encode_key2text.c` publishes,
 * through the public `OSSL_ENCODER_*` surface, and compares the transcript byte for byte against
 * the authority's.
 *
 * ## The three joins section 3.1 names
 *
 * A codec that round-trips is not a codec. This probe observes the row at all three joins the plan
 * requires:
 *
 *   1. **Identity.** `arm_identity` fetches each row by name through each provider with an
 *      `output=text` property query, and prints `OSSL_ENCODER_get0_name` and
 *      `OSSL_ENCODER_get0_properties`. Those are the row's `algorithm_names` and
 *      `property_definition`, read back through the fetched object rather than from a table; a row
 *      whose bytes are right but whose published identity differs is a residual here.
 *   2. **Behaviour.** Each `arm_*` builds a key from a *fixed, non-secret* probe constant through
 *      the keymgmt row, then encodes it with `OSSL_ENCODER_CTX_new_for_pkey(pkey, selection,
 *      "TEXT", ...)` and prints the encoder count and the exact bytes `OSSL_ENCODER_to_data`
 *      produced, as hex. The bytes are the authority's contract: the label layout, the
 *      decimal-with-hex small-value form and the 15-byte hex blocks all show up here.
 *   3. **The refusal arm.** `arm_ec_refusal` encodes a *parameters-only* EC key with a keypair
 *      selection, which is the printer's own `PROV_R_NOT_A_PRIVATE_KEY` arm, and prints the return
 *      and the error queue.
 *
 * ## Why the constants are public and fixed
 *
 * Every key is imported from a published input: the RFC 7748/8032 base points for the four ECX
 * types, the NIST P-256 and SM2 named groups for EC/SM2, and FFDHE-2048 for DH. None is generated,
 * because a generated key differs between two runs and a differential transcript must be a
 * function of its inputs alone. No private value is printed; the keys are parameters and public
 * points.
 *
 * ## What is not driven, and why
 *
 * The four `RSA`/`RSA-PSS`/`DSA`/`DHX` rows are observed at join 1 only. `RSA` and `DSA` need a
 * full private key or a modulus the probe would have to carry, and `DHX`'s named groups are a
 * different set from `DH`'s. The eighteen PQC text rows the authority publishes are **not**
 * published by this crate: their `*_to_text` helpers live in unlanded units, so no arm may fetch
 * them without the candidate answering differently (docs/PHASE-10-SUBPHASES.md section 3.5).
 */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/core_names.h>

static void kv_int(const char *key, int value)
{
    printf("%s=%d\n", key, value);
}

static void kv_str(const char *key, const char *value)
{
    printf("%s=%s\n", key, value == NULL ? "(null)" : value);
}

static void kv_hex(const char *key, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s.len=%zu\n", key, len);
    printf("%s.hex=", key);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* The error queue, normalised to the two portable fields (docs/PARITY_MODEL.md's ERROR_PASS). */
static void errs(const char *key)
{
    unsigned long e;
    int i = 0;

    while ((e = ERR_get_error()) != 0)
        printf("%s.%d=lib=%d,reason=%d\n", key, i++, ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("%s.count=%d\n", key, i);
}

/* The eleven rows this unit publishes, in the authority's deflt_encoder[] order, and the two
 * providers that publish a copy of each (defltprov.c and baseprov.c). */
static const char *codec_rows[] = {
    "RSA", "RSA-PSS", "DH", "DHX", "DSA", "EC", "ED25519", "ED448", "X25519", "X448", "SM2"
};
static const char *providers[] = { "default", "base" };

/* Join 1: the row's identity through the provider that publishes it. */
static void arm_identity(void)
{
    size_t i, j;

    for (j = 0; j < sizeof(providers) / sizeof(providers[0]); j++) {
        for (i = 0; i < sizeof(codec_rows) / sizeof(codec_rows[0]); i++) {
            char prop[64], key[64];
            OSSL_ENCODER *enc;

            snprintf(prop, sizeof(prop), "provider=%s,output=text", providers[j]);
            snprintf(key, sizeof(key), "codec.%s.%s", providers[j], codec_rows[i]);
            enc = OSSL_ENCODER_fetch(NULL, codec_rows[i], prop);
            kv_int("codec.fetch", enc != NULL);
            if (enc != NULL) {
                kv_str("codec.name", OSSL_ENCODER_get0_name(enc));
                kv_str("codec.props", OSSL_ENCODER_get0_properties(enc));
                kv_int("codec.is_a_self", OSSL_ENCODER_is_a(enc, codec_rows[i]));
                kv_int("codec.is_a_text", OSSL_ENCODER_is_a(enc, "text"));
            }
            OSSL_ENCODER_free(enc);

            /* A name no provider holds: the fetch's own refusal, identical on both sides. Its
             * error is dropped so it cannot colour the behavioural arms' queues. */
            if (j == 0 && i == 0) {
                enc = OSSL_ENCODER_fetch(NULL, "NOSUCH-CODEC", "output=text");
                kv_int("codec.fetch.no_row", enc != NULL);
                OSSL_ENCODER_free(enc);
                ERR_clear_error();
            }
        }
        ERR_clear_error();
    }
}

/* Join 2: encode a key this arm built and print the exact bytes. */
static void encode_and_report(const char *key, EVP_PKEY *pkey, int selection)
{
    OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "TEXT", NULL, NULL);
    unsigned char *data = NULL;
    size_t len = 0;
    int rc;

    /* Only the encode's own errors are observed: a cleared queue makes that exact. */
    ERR_clear_error();
    rc = OSSL_ENCODER_to_data(ctx, &data, &len);
    kv_int("codec.to_data", rc);
    if (rc == 1 && data != NULL)
        kv_hex(key, data, len);
    OPENSSL_free(data);
    OSSL_ENCODER_CTX_free(ctx);
    errs(key);
}

/* Build a parameters-only key of `type` on named `group`, or NULL. */
static EVP_PKEY *params_key(const char *type, const char *group)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    OSSL_PARAM params[2];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_fromdata_init(ctx) != 1)
        goto out;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)group, 0);
    params[1] = OSSL_PARAM_construct_end();
    (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params);
out:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* The published ECX public constants, the same ones `rt_keymgmt_probe.c` imports: RFC 7748's base
 * points (X25519 u = 9, X448 u = 5) and RFC 8032 section 7.1/7.4 test vector 1's public keys. */
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
};

static const struct ecx_row ecx_rows[] = {
    { "X25519", x25519_pub, sizeof(x25519_pub) },
    { "X448", x448_pub, sizeof(x448_pub) },
    { "ED25519", ed25519_pub, sizeof(ed25519_pub) },
    { "ED448", ed448_pub, sizeof(ed448_pub) }
};

/* ECX public keys, encoded with the public-key selection: the printer's public arm. */
static void arm_ecx_public(void)
{
    size_t i;

    for (i = 0; i < sizeof(ecx_rows) / sizeof(ecx_rows[0]); i++) {
        const struct ecx_row *r = &ecx_rows[i];
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, r->name, NULL);
        OSSL_PARAM params[2];
        EVP_PKEY *pkey = NULL;
        char key[64];

        if (ctx == NULL)
            continue;
        (void)EVP_PKEY_fromdata_init(ctx);
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                      (void *)r->pub, r->publen);
        params[1] = OSSL_PARAM_construct_end();
        kv_int("ecx.import", EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params));
        snprintf(key, sizeof(key), "codec.ecx.%s", r->name);
        if (pkey != NULL)
            encode_and_report(key, pkey, EVP_PKEY_PUBLIC_KEY);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
    }
}

/* EC and SM2 parameters on their named groups, and DH parameters on FFDHE-2048: the printer's
 * parameters arm, over the named-curve branch of `ec_param_to_text` and the `GROUP:` branch of
 * `ossl_bio_print_ffc_params`. */
static void arm_named_params(void)
{
    static const struct {
        const char *type;
        const char *group;
        const char *key;
    } rows[] = {
        { "EC", "prime256v1", "codec.ec.params" },
        { "SM2", "SM2", "codec.sm2.params" },
        { "DH", "ffdhe2048", "codec.dh.params" }
    };
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        EVP_PKEY *pkey = params_key(rows[i].type, rows[i].group);

        kv_int("codec.params.built", pkey != NULL);
        if (pkey != NULL)
            encode_and_report(rows[i].key, pkey, EVP_PKEY_KEY_PARAMETERS);
        EVP_PKEY_free(pkey);
    }
}

/* Join 3: the printer's own refusal. An EC key that carries only parameters is asked to encode as
 * a keypair, so `ec_to_text`'s `EC_KEY_get0_private_key` check refuses with
 * `PROV_R_NOT_A_PRIVATE_KEY` and the error queue carries the site. */
static void arm_ec_refusal(void)
{
    EVP_PKEY *pkey = params_key("EC", "prime256v1");

    kv_int("codec.refusal.built", pkey != NULL);
    if (pkey != NULL)
        encode_and_report("codec.ec.refuse_private", pkey, EVP_PKEY_KEYPAIR);
    EVP_PKEY_free(pkey);
}

int main(void)
{
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *base = OSSL_PROVIDER_load(NULL, "base");

    kv_int("codec.provider.default", deflt != NULL);
    kv_int("codec.provider.base", base != NULL);

    arm_identity();
    arm_ecx_public();
    arm_named_params();
    arm_ec_refusal();

    OSSL_PROVIDER_unload(base);
    OSSL_PROVIDER_unload(deflt);
    return 0;
}
