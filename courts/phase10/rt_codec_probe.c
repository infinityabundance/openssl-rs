/*
 * RT-CODEC -- Phase 10.1's provider codec court, over the encoder and decoder rows 10.1 lands.
 *
 * This is the first behavioural court of the key-format stratum. Until it, the only probe Phase 10
 * had (`rt_coverage_ref_probe.c`) took the *address* of the eighty-seven inherited exports and
 * claimed nothing about any of them; every one of this stratum's own rows was unimplemented. This
 * probe drives the rows `providers/implementations/encode_decode/encode_key2text.c` (the text
 * encoders), `encode_key2blob.c` (the `EC`/`SM2` public-point blob encoders), `encode_key2ms.c`
 * (the `RSA`/`DSA` `msblob`/`pvk` encoders, since 10.6) and `decode_epki2pki.c`
 * (the `EncryptedPrivateKeyInfo`-to-`PrivateKeyInfo` decoder) and `decode_msblob2key.c`/
 * `decode_pvk2key.c` (the `msblob`/`pvk` decoders, since 10.6) publish, through the public
 * `OSSL_ENCODER_*`/`OSSL_DECODER_*` surface, and compares the transcript byte for byte against
 * the authority's.
 *
 * ## The three joins section 3.1 names
 *
 * A codec that round-trips is not a codec. This probe observes each row at all three joins the plan
 * requires:
 *
 *   1. **Identity.** `arm_identity` fetches each text row by name through each provider with an
 *      `output=text` property query, `arm_blob_identity` the blob rows with `output=blob`, and
 *      `arm_decoder_identity` the decoder row with `input=der,structure=EncryptedPrivateKeyInfo`;
 *      each prints `get0_name` and `get0_properties`. Those are the row's `algorithm_names` and
 *      `property_definition`, read back through the fetched object rather than from a table; a row
 *      whose bytes are right but whose published identity differs is a residual here.
 *   2. **Behaviour.** Each `arm_*` builds a key from a *fixed, non-secret* probe constant through
 *      the keymgmt row, then encodes it with `OSSL_ENCODER_CTX_new_for_pkey(pkey, selection,
 *      "TEXT"/"blob", ...)` and prints the encoder count and the exact bytes
 *      `OSSL_ENCODER_to_data` produced, as hex. For the decoder, `arm_decoder_decode` drives the
 *      fetched row over the fixed `EncryptedPrivateKeyInfo` vector the authority's own tree carries
 *      (`test/certs/key-pass-12345.pem`, passphrase "12345") through `OSSL_DECODER_from_data` with
 *      a construct callback, and prints the object type, data type, structure and the exact
 *      `PrivateKeyInfo` octets. The bytes are the authority's contract.
 *   3. **The refusal arms.** `arm_ec_refusal` encodes a *parameters-only* EC key with a keypair
 *      selection (the printer's `PROV_R_NOT_A_PRIVATE_KEY` arm); `arm_blob_refusal` asks the blob
 *      row for a keypair selection, which its `does_selection` refuses; and `arm_decoder_refusal`
 *      drives the decoder with no passphrase set, which the framework's callback refuses with
 *      `PROV_R_UNABLE_TO_GET_PASSPHRASE`. Each prints the return and the error queue.
 *
 * ## Why the constants are public and fixed
 *
 * Every key is imported from a published input: the RFC 7748/8032 base points for the four ECX
 * types, the NIST P-256 and SM2 named groups for EC/SM2, the P-256 and SM2 curve generators for
 * the two blob arms, FFDHE-2048 for DH, and the authority's own PKCS#8 `EncryptedPrivateKeyInfo`
 * vector (`test/certs/key-pass-12345.pem`) for the decoder. None is generated, because a generated
 * key (or salt) differs between two runs and a differential transcript must be a function of its
 * inputs alone. No private value is printed; the keys are parameters and public points.
 *
 * ## What is not driven, and why
 *
 * The four `RSA`/`RSA-PSS`/`DSA`/`DHX` **text** encoder rows are observed at join 1 only. The
 * text printer needs a full private key for `RSA`/`DSA` and `DHX`'s named groups are a different
 * set from `DH`'s. The MSBLOB/PVK rows below are a different matter: those writers take a bare
 * key, so the fixed RSA and 160-bit-`q` DSA keypairs `rt_keyformat_keys.h` carries do drive them
 * (`RSA`/`RSA-PSS`/`DSA`/`DHX` here means the `output=text` rows, not the `output=msblob`/
 * `output=pvk` ones). The eighteen PQC text rows are published and driven: ML-KEM and
 * ML-DSA from the fixed keygen seeds Phase 8's probes carry, and SLH-DSA from the twelve ACVP
 * private keys (`../phase8/ml_kem_probe.h`, `ml_dsa_probe.h`, `slh_dsa_probe.h`). The three codec
 * units' `d2i`/`i2d` half is reached by `decode_der2key.c`, which landed with 10.1; the decoder
 * arms below drive the rows it publishes, and the encoder half (`encode_key2any.c`) is still open.
 *
 * ## The `decode_der2key.c` rows
 *
 * The sixty-nine `decode_der2key.c` rows and the `decode_epki2pki.c` row they share a table with
 * are driven in the dedicated section below: identity for all seventy rows in both providers, a
 * fixed-input behaviour arm wherever the key type's own stratum is landable, and named `pending`
 * reasons for the rest (docs/PHASE-10-SUBPHASES.md sections 3.1 and 3.5).
 */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>

/* The fixed PQC key inputs Phase 8's probes already carry: an ML-KEM `(d, z)` seed and
 * encapsulation key per variant, an ML-DSA keygen seed, and the twelve SLH-DSA ACVP private
 * keys. They are the same published/differential inputs those courts use, so the bytes this
 * court encodes are a function of its inputs alone. */
#include "../phase8/ml_kem_probe.h"
#include "../phase8/ml_dsa_probe.h"
#include "../phase8/slh_dsa_probe.h"

/* The fixed RSA and DSA keypairs 10.6's court (`rt_keyformat_probe.c`) already carries; the
 * MSBLOB/PVK rows below encode the same deterministic inputs that probe compares bytes for. */
#include "rt_keyformat_keys.h"

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

/* The twenty-nine rows this unit publishes, in the authority's deflt_encoder[] order, and the two
 * providers that publish a copy of each (defltprov.c and baseprov.c). The eighteen PQC rows were
 * withheld until their `*_to_text` helpers landed (docs/PHASE-10-SUBPHASES.md section 3.5); they
 * are published now, so the whole MAKE_TEXT_ENCODER list is named here. */
static const char *codec_rows[] = {
    "RSA", "RSA-PSS", "DH", "DHX", "DSA", "EC", "ED25519", "ED448", "X25519", "X448", "SM2",
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
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

/* ---------------------------------------------------------------------------
 * The two blob encoder rows `encode_key2blob.c` publishes.
 *
 * Join 1: the row's identity through the provider, with an `output=blob` query.
 * ------------------------------------------------------------------------- */
static const char *blob_rows[] = { "EC", "SM2" };

static void arm_blob_identity(void)
{
    size_t i, j;

    for (j = 0; j < sizeof(providers) / sizeof(providers[0]); j++) {
        for (i = 0; i < sizeof(blob_rows) / sizeof(blob_rows[0]); i++) {
            char prop[64];
            OSSL_ENCODER *enc;

            snprintf(prop, sizeof(prop), "provider=%s,output=blob", providers[j]);
            enc = OSSL_ENCODER_fetch(NULL, blob_rows[i], prop);
            kv_int("blob.fetch", enc != NULL);
            if (enc != NULL) {
                kv_str("blob.name", OSSL_ENCODER_get0_name(enc));
                kv_str("blob.props", OSSL_ENCODER_get0_properties(enc));
                kv_int("blob.is_a_self", OSSL_ENCODER_is_a(enc, blob_rows[i]));
                kv_int("blob.is_a_blob", OSSL_ENCODER_is_a(enc, "blob"));
            }
            OSSL_ENCODER_free(enc);
        }
        ERR_clear_error();
    }
}

/* The P-256 and SM2 generator points, the published public constants the two blob rows encode.
 * They are the curve generators, so `i2o_ECPublicKey` writes them uncompressed (`04 || X || Y`). */
static const unsigned char p256_g_pub[65] = {
    0x04,
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};
static const unsigned char sm2_g_pub[65] = {
    0x04,
    0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
    0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
    0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
    0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
    0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
    0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
    0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
    0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0
};

/* Build a public-key-only EC/SM2 key from a fixed point, or NULL. */
static EVP_PKEY *point_key(const char *type, const char *group,
    const unsigned char *pub, size_t publen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    OSSL_PARAM params[3];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_fromdata_init(ctx) != 1)
        goto out;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)group, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (void *)pub, publen);
    params[2] = OSSL_PARAM_construct_end();
    (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
out:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Join 2: encode the fixed public points with the blob rows and print the exact bytes. */
static void arm_blob_public(void)
{
    struct {
        const char *type;
        const char *group;
        const unsigned char *pub;
        size_t publen;
        const char *key;
    } rows[] = {
        { "EC", "prime256v1", p256_g_pub, sizeof(p256_g_pub), "blob.ec.pub" },
        { "SM2", "SM2", sm2_g_pub, sizeof(sm2_g_pub), "blob.sm2.pub" }
    };
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        EVP_PKEY *pkey = point_key(rows[i].type, rows[i].group,
            rows[i].pub, rows[i].publen);
        kv_int("blob.built", pkey != NULL);
        if (pkey != NULL)
            encode_and_report(rows[i].key, pkey, EVP_PKEY_PUBLIC_KEY);
        EVP_PKEY_free(pkey);
    }
}

/* Join 3: the blob row's own selection refusal. A keypair selection does not have the
 * public-key bit's `does_selection` answer, so the framework finds no encoder. */
static void arm_blob_refusal(void)
{
    EVP_PKEY *pkey = point_key("EC", "prime256v1", p256_g_pub, sizeof(p256_g_pub));

    kv_int("blob.refusal.built", pkey != NULL);
    if (pkey != NULL)
        encode_and_report("blob.ec.refuse_keypair", pkey, EVP_PKEY_KEYPAIR);
    EVP_PKEY_free(pkey);
}

/* ---------------------------------------------------------------------------
 * The one decoder row `decode_epki2pki.c` publishes.
 *
 * The fixed input is `test/certs/key-pass-12345.pem`'s body, the authority's own published
 * PKCS#8 `EncryptedPrivateKeyInfo` vector (PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC, passphrase
 * "12345"). A constant both sides read is the input, not the expectation.
 * ------------------------------------------------------------------------- */

static const unsigned char epki_der[1329] = {
    0x30, 0x82, 0x05, 0x2d, 0x30, 0x57, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x05, 0x0d, 0x30, 0x4a, 0x30, 0x29, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c, 0x30, 0x1c, 0x04, 0x08,
    0xb8, 0x7f, 0x17, 0xd7, 0x15, 0xa5, 0xf7, 0x28, 0x02, 0x02, 0x08, 0x00,
    0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09,
    0x05, 0x00, 0x30, 0x1d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x01, 0x2a, 0x04, 0x10, 0xb0, 0xdb, 0xb5, 0x07, 0x0e, 0xe0, 0x6d,
    0xc5, 0x66, 0xbd, 0xdb, 0xc0, 0x17, 0x10, 0x46, 0xf5, 0x04, 0x82, 0x04,
    0xd0, 0x0f, 0xda, 0x1f, 0xf9, 0xcc, 0x1a, 0x88, 0x9f, 0x03, 0x84, 0xca,
    0xa4, 0xb8, 0x35, 0x4a, 0x86, 0xec, 0x92, 0xe8, 0x33, 0x59, 0x5e, 0xfe,
    0x37, 0x6a, 0xa1, 0xde, 0x3f, 0x4b, 0x66, 0xbc, 0xfa, 0x1b, 0x10, 0x7d,
    0x8d, 0x1e, 0xb8, 0x24, 0x1c, 0x7c, 0xf9, 0xe2, 0x81, 0xbb, 0x99, 0x6f,
    0x55, 0xe3, 0x29, 0xfd, 0xc2, 0x2e, 0x19, 0x9b, 0x1c, 0x27, 0x9e, 0x90,
    0x15, 0x9d, 0x35, 0xb5, 0x31, 0x32, 0x22, 0x23, 0xf5, 0x79, 0xe0, 0xfa,
    0xf1, 0xe4, 0x28, 0x97, 0x69, 0xfb, 0x28, 0x4c, 0x24, 0xf4, 0x32, 0xa4,
    0x47, 0x64, 0x1b, 0x42, 0xe2, 0xc3, 0x39, 0xa4, 0x78, 0xbe, 0x8a, 0x8c,
    0xae, 0x6d, 0x36, 0xb9, 0xe8, 0x4b, 0x9c, 0xd3, 0xc9, 0xed, 0xdf, 0x35,
    0x0a, 0xb8, 0x1f, 0xa8, 0x84, 0x62, 0xe4, 0xe1, 0x78, 0x71, 0x65, 0x55,
    0xdb, 0x48, 0xcd, 0xee, 0x94, 0x0c, 0xc6, 0x7f, 0x0a, 0xa9, 0x6e, 0x0e,
    0x60, 0xf7, 0x4e, 0xad, 0x5d, 0x62, 0xea, 0x64, 0xe7, 0xb1, 0xb3, 0x73,
    0x33, 0x98, 0x4b, 0xf5, 0x83, 0x2e, 0x77, 0x8c, 0x29, 0xa5, 0x6c, 0x00,
    0xf7, 0x73, 0x0b, 0x0f, 0x84, 0xc6, 0xbd, 0x00, 0x50, 0x49, 0x3b, 0xeb,
    0x79, 0x8b, 0x4b, 0x37, 0x2d, 0x5a, 0xb6, 0xad, 0x6e, 0x2b, 0x89, 0x36,
    0x29, 0x98, 0x76, 0xb7, 0x0f, 0xc2, 0x4c, 0xd8, 0x82, 0xa3, 0x8e, 0xd1,
    0x37, 0xa1, 0x6d, 0xf8, 0x20, 0xc9, 0x6e, 0x58, 0xa4, 0xa1, 0xda, 0x63,
    0xfd, 0xae, 0x99, 0x3c, 0x9f, 0x38, 0xa8, 0x13, 0x28, 0x9d, 0x36, 0xdc,
    0xec, 0x83, 0x2f, 0x91, 0xe5, 0x8f, 0xd2, 0x69, 0xf3, 0x03, 0x6e, 0x68,
    0x84, 0xe5, 0xbb, 0x45, 0xf8, 0x60, 0x5b, 0x3c, 0xff, 0x99, 0xfc, 0x77,
    0xff, 0x2a, 0x57, 0xf3, 0x1a, 0x8b, 0x77, 0xc2, 0x73, 0x99, 0xd4, 0x45,
    0x39, 0xc7, 0x39, 0x30, 0x57, 0x55, 0x71, 0x83, 0xe6, 0x80, 0x5c, 0xc5,
    0x56, 0xd1, 0x09, 0xd1, 0xb0, 0x59, 0xc7, 0xa5, 0x82, 0x5b, 0xee, 0x8e,
    0xb3, 0x32, 0xe4, 0xb7, 0xfe, 0xe9, 0xee, 0xb6, 0x91, 0x2a, 0x2a, 0xc0,
    0xff, 0x32, 0x49, 0x48, 0x19, 0x84, 0xbd, 0x02, 0xaf, 0xc2, 0xd6, 0x7a,
    0x23, 0xfa, 0xc6, 0xe9, 0x2a, 0x8c, 0x16, 0x24, 0xec, 0x79, 0x1b, 0x96,
    0xab, 0x4b, 0x17, 0x6b, 0x53, 0x57, 0xdb, 0x39, 0x47, 0xf7, 0x2f, 0xa0,
    0xeb, 0xc2, 0xbe, 0xec, 0x1b, 0x79, 0xf3, 0x5e, 0xa5, 0xf7, 0x75, 0x83,
    0xa7, 0x41, 0x90, 0x81, 0x6c, 0x57, 0x57, 0x62, 0x7e, 0x40, 0x9d, 0xdf,
    0x1a, 0xfc, 0x4c, 0x75, 0x01, 0xbb, 0xaa, 0x61, 0x96, 0xc7, 0xa7, 0x5c,
    0xeb, 0x26, 0x64, 0x17, 0x0f, 0x5e, 0xf7, 0x8b, 0x13, 0x1c, 0x7e, 0xf8,
    0x7d, 0x28, 0x53, 0xbf, 0x9d, 0xce, 0x7a, 0x40, 0xa0, 0x5a, 0x0d, 0x81,
    0xe7, 0xca, 0x45, 0x05, 0x32, 0xbd, 0x34, 0x6b, 0x62, 0x1b, 0x92, 0xda,
    0xc2, 0xd0, 0xca, 0x32, 0xa9, 0x58, 0x71, 0x22, 0xaf, 0x7e, 0xa8, 0xef,
    0x2b, 0x00, 0xe8, 0x91, 0x04, 0xb5, 0xd3, 0x80, 0xf0, 0x33, 0xea, 0x26,
    0xd1, 0x00, 0x4b, 0x4c, 0x7f, 0x91, 0x47, 0x18, 0x74, 0xe6, 0x36, 0x2f,
    0xda, 0x1c, 0x75, 0xbb, 0x04, 0x97, 0xa2, 0x8f, 0x28, 0x3b, 0xe0, 0x18,
    0x69, 0x8b, 0x04, 0x40, 0x4f, 0x33, 0xee, 0x66, 0x31, 0x42, 0xbe, 0x44,
    0x6b, 0x58, 0x0a, 0x6e, 0xdc, 0x98, 0x3c, 0x4d, 0x04, 0xa3, 0x9a, 0xeb,
    0x1f, 0xd7, 0xd8, 0xcd, 0x73, 0x7c, 0x03, 0x52, 0xc7, 0xef, 0x06, 0xcb,
    0xcb, 0x04, 0x08, 0x66, 0xaf, 0xe5, 0xb6, 0x1b, 0x89, 0x19, 0xaa, 0xd3,
    0x3c, 0x21, 0x63, 0xa0, 0x7a, 0xcf, 0x5b, 0xd3, 0xbe, 0x16, 0x24, 0x01,
    0x2e, 0xc9, 0xf9, 0x12, 0x3d, 0x95, 0x56, 0x6d, 0x8c, 0x42, 0x94, 0xb7,
    0xbf, 0xa9, 0xbb, 0x4a, 0x71, 0xd3, 0x58, 0x16, 0x8f, 0x66, 0xf9, 0x2a,
    0x18, 0x41, 0xb0, 0xfc, 0xc6, 0x62, 0xc2, 0x4c, 0xf2, 0x50, 0xbb, 0x20,
    0xef, 0x34, 0x4a, 0x7e, 0x73, 0x61, 0x60, 0x17, 0xf1, 0x76, 0x0f, 0xa0,
    0x9b, 0x02, 0x11, 0xeb, 0x1d, 0x5e, 0xe2, 0xf4, 0xfa, 0x84, 0x01, 0x63,
    0x65, 0xbb, 0xe7, 0xd5, 0xe3, 0xa5, 0x15, 0x32, 0xea, 0x20, 0x1a, 0x44,
    0x5d, 0x00, 0xaa, 0xc5, 0xa2, 0x13, 0xb5, 0x6e, 0x9b, 0x08, 0x48, 0x6f,
    0x97, 0xf7, 0x34, 0x00, 0xa9, 0x00, 0x58, 0xcd, 0xfd, 0x5c, 0x4b, 0x3f,
    0x7d, 0xfd, 0x60, 0x89, 0x8c, 0xda, 0xfb, 0xa4, 0x8b, 0x80, 0xb4, 0x0e,
    0x6c, 0x70, 0x29, 0xa7, 0xe4, 0x3f, 0x1e, 0x4d, 0xcf, 0x69, 0x40, 0xea,
    0x5a, 0x79, 0xbf, 0xe7, 0x0f, 0x08, 0xc9, 0x07, 0x06, 0x0c, 0x08, 0xa4,
    0xd1, 0xfe, 0x89, 0xa9, 0xb4, 0x3e, 0x96, 0x27, 0x01, 0x93, 0x99, 0x47,
    0x94, 0xe8, 0x9f, 0x3b, 0x41, 0x85, 0x2a, 0xa7, 0x8f, 0x94, 0xa2, 0xd8,
    0xfc, 0xcb, 0xf1, 0xf5, 0xa9, 0x76, 0x51, 0xf9, 0x73, 0x3b, 0x27, 0x46,
    0xbb, 0xd0, 0x69, 0x5f, 0x1f, 0x2c, 0x2e, 0x8a, 0x0b, 0xbb, 0x2c, 0x9c,
    0x5c, 0x58, 0x60, 0xa5, 0x96, 0x4b, 0xa7, 0x5f, 0x7e, 0xef, 0xd2, 0xa0,
    0x3e, 0x6f, 0x99, 0xad, 0x72, 0xa5, 0x28, 0xac, 0x13, 0x0d, 0x0c, 0x2e,
    0x07, 0xe7, 0x86, 0xc6, 0xbd, 0xb0, 0x29, 0x60, 0x9b, 0x25, 0xbd, 0xb2,
    0x82, 0x69, 0xc1, 0x0a, 0xd9, 0xa5, 0xe5, 0xaa, 0x53, 0x43, 0x1f, 0xa5,
    0xeb, 0x7d, 0x06, 0x95, 0xd3, 0x23, 0x92, 0x1c, 0x31, 0x39, 0x26, 0x49,
    0xa1, 0x7c, 0xba, 0x5c, 0xa4, 0x1e, 0xc3, 0xce, 0x4b, 0xfc, 0x9f, 0x49,
    0x92, 0x7b, 0x5a, 0xdd, 0xb8, 0xc6, 0x6f, 0x22, 0xf6, 0x94, 0x47, 0x96,
    0xfe, 0x07, 0xd3, 0xf8, 0xbe, 0x96, 0xae, 0x61, 0xb7, 0x1d, 0xfe, 0x31,
    0x1a, 0x1a, 0x64, 0x93, 0x1e, 0x94, 0x21, 0x3c, 0xee, 0x8c, 0x96, 0xc4,
    0xdb, 0xf6, 0x32, 0xc4, 0x9f, 0xac, 0x5e, 0x54, 0x6e, 0x61, 0xde, 0x25,
    0x77, 0x41, 0xdf, 0x9f, 0xa2, 0x21, 0xb1, 0xa8, 0xe4, 0x9e, 0x3f, 0x06,
    0x8e, 0xf2, 0xdb, 0xef, 0xb1, 0x6f, 0x80, 0xd9, 0xdd, 0x7f, 0x94, 0x97,
    0x96, 0xa5, 0x37, 0xb0, 0xc1, 0x9c, 0x38, 0xf8, 0xb3, 0x42, 0x43, 0x2b,
    0xfc, 0x09, 0xad, 0x1c, 0xfc, 0xc1, 0x2d, 0x3f, 0x0e, 0xe8, 0xec, 0x69,
    0x78, 0x03, 0x96, 0xcc, 0x6d, 0xe3, 0x3a, 0xfc, 0xe7, 0x46, 0xc9, 0x99,
    0xdb, 0xb9, 0xe6, 0x5b, 0x87, 0x0c, 0xff, 0xab, 0x7f, 0xf3, 0xa3, 0xef,
    0x9c, 0x0b, 0x2c, 0x3c, 0x44, 0xc5, 0x72, 0xb0, 0xb7, 0x1a, 0xa1, 0x58,
    0x5a, 0x7c, 0xdd, 0x55, 0xa5, 0xae, 0x9c, 0x2c, 0xf9, 0xce, 0x7e, 0x31,
    0x22, 0x8b, 0x77, 0xeb, 0x7d, 0xd5, 0x19, 0x1d, 0x65, 0x6f, 0x15, 0xf8,
    0x91, 0x34, 0x0b, 0x07, 0x38, 0x01, 0x8c, 0xab, 0x9a, 0x8e, 0x05, 0x62,
    0x9b, 0x94, 0x38, 0xa1, 0xb7, 0xda, 0xaa, 0x72, 0x44, 0xbc, 0x79, 0x1b,
    0x25, 0xa0, 0x05, 0x26, 0x0d, 0x32, 0xea, 0xe2, 0x1d, 0xd9, 0x12, 0x33,
    0x62, 0x8e, 0x7f, 0xa2, 0x71, 0xeb, 0x54, 0xe4, 0x11, 0xe6, 0xe9, 0x41,
    0xab, 0x24, 0x7c, 0x60, 0x98, 0xd6, 0xbb, 0x7a, 0x72, 0xab, 0xcb, 0x79,
    0xab, 0xd2, 0x30, 0xdc, 0xbf, 0xa9, 0x58, 0x33, 0xa1, 0xe0, 0x01, 0xfb,
    0xfd, 0xac, 0xb4, 0x20, 0x1b, 0xbf, 0xab, 0x16, 0xa9, 0xbf, 0x26, 0xea,
    0x11, 0x7c, 0xa8, 0x97, 0x79, 0x00, 0x24, 0x8b, 0x18, 0xd0, 0x02, 0x99,
    0x63, 0x97, 0x4f, 0x03, 0x87, 0x6e, 0x5a, 0x35, 0xb4, 0x30, 0x73, 0x43,
    0x82, 0x58, 0x80, 0xb2, 0xc2, 0xab, 0xda, 0xdd, 0xc2, 0x4c, 0x02, 0xd4,
    0xf6, 0x7a, 0xc1, 0x55, 0x7d, 0x5f, 0x10, 0xf4, 0x78, 0x63, 0x4e, 0x49,
    0x67, 0xd7, 0xf8, 0x38, 0x8b, 0x9e, 0xbb, 0xf2, 0x06, 0x74, 0x32, 0x04,
    0xb2, 0x72, 0xdd, 0xaa, 0xd9, 0x18, 0xd2, 0xc3, 0x93, 0x99, 0xaf, 0x45,
    0x84, 0xa0, 0xef, 0xd5, 0x1c, 0x2c, 0xba, 0x64, 0xff, 0x51, 0xf3, 0xaa,
    0x50, 0x9d, 0xd9, 0x48, 0x90, 0x9a, 0x2a, 0x01, 0x3f, 0x46, 0x7c, 0xd2,
    0xdd, 0x83, 0x7e, 0x8f, 0x90, 0x58, 0xbf, 0xbf, 0x3c, 0x9a, 0x27, 0x19,
    0x4b, 0xd9, 0xe5, 0xe4, 0xa5, 0xfe, 0xab, 0xf5, 0x52, 0x55, 0x7c, 0x62,
    0x6a, 0x5d, 0x27, 0xc6, 0x41, 0xa2, 0xaa, 0xce, 0xf7, 0x98, 0x04, 0x85,
    0xe4, 0x93, 0xf8, 0x89, 0xaa, 0xd1, 0x8a, 0x14, 0xa7, 0xb4, 0x63, 0x2f,
    0x9f, 0x83, 0xcf, 0x07, 0xb3, 0xa2, 0x77, 0x94, 0x95, 0x2e, 0xba, 0xa4,
    0x24, 0x51, 0x72, 0xee, 0x98, 0xcb, 0xf3, 0x1b, 0x84, 0x47, 0x1d, 0x21,
    0x95, 0x28, 0x54, 0x97, 0x6a, 0xbc, 0xfc, 0x2d, 0xc3, 0x4a, 0x2d, 0x2e,
    0xf9, 0x09, 0x08, 0x84, 0xda, 0xd4, 0x04, 0xa6, 0x51, 0x00, 0x3c, 0xcd,
    0x0e, 0x42, 0x5c, 0x7d, 0x69, 0x8a, 0xc1, 0xb8, 0x6a, 0xec, 0x73, 0xe9,
    0x82, 0x1c, 0xef, 0x68, 0x3a, 0xc5, 0xb4, 0x7f, 0xf8, 0xa3, 0xcb, 0x7b,
    0x91, 0xdf, 0x93, 0x55, 0xd2, 0xa3, 0x9d, 0x2d, 0x1c, 0x9d, 0xae, 0x37,
    0x4a, 0x3f, 0x78, 0xc3, 0x72, 0x79, 0xff, 0x2e, 0x58,
};

/* The decoder's construct callback: it prints the object's type, data type, structure and the
 * exact octets of the `PrivateKeyInfo` the epki row handed over, then accepts the object. */
static int decoder_construct(OSSL_DECODER_INSTANCE *decoder_inst,
    const OSSL_PARAM *params, void *construct_data)
{
    const OSSL_PARAM *p;
    char *str = NULL;
    const char *key = construct_data;

    (void)decoder_inst;
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_TYPE);
    if (p != NULL)
        kv_int("dec.type", *(const int *)p->data);
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
    if (p != NULL && OSSL_PARAM_get_utf8_string_ptr(p, &str) == 1)
        kv_str("dec.data_type", str);
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_INPUT_TYPE);
    if (p != NULL && OSSL_PARAM_get_utf8_string_ptr(p, &str) == 1)
        kv_str("dec.input_type", str);
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_STRUCTURE);
    if (p != NULL && OSSL_PARAM_get_utf8_string_ptr(p, &str) == 1)
        kv_str("dec.data_structure", str);
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA);
    if (p != NULL)
        kv_hex("dec.data", p->data, p->data_size);
    printf("%s=1\n", key);
    return 1;
}

/* Join 1: the decoder row's identity, with the `input=der,structure=EncryptedPrivateKeyInfo`
 * query the row's property names. */
static void arm_decoder_identity(void)
{
    size_t j;

    for (j = 0; j < sizeof(providers) / sizeof(providers[0]); j++) {
        char prop[128];
        OSSL_DECODER *dec;

        snprintf(prop, sizeof(prop),
                 "provider=%s,input=der,structure=EncryptedPrivateKeyInfo",
                 providers[j]);
        dec = OSSL_DECODER_fetch(NULL, "DER", prop);
        kv_int("dec.fetch", dec != NULL);
        if (dec != NULL) {
            kv_str("dec.name", OSSL_DECODER_get0_name(dec));
            kv_str("dec.props", OSSL_DECODER_get0_properties(dec));
            kv_int("dec.is_a_der", OSSL_DECODER_is_a(dec, "DER"));
        }
        OSSL_DECODER_free(dec);
        ERR_clear_error();
    }
}

/* Drive the fetched row over the fixed input and report the callback's transcript. */
static void decoder_run(const char *key, int with_passphrase)
{
    OSSL_DECODER *dec = OSSL_DECODER_fetch(NULL, "DER",
        "provider=default,input=der,structure=EncryptedPrivateKeyInfo");
    OSSL_DECODER_CTX *ctx;
    const unsigned char *p = epki_der;
    size_t len = sizeof(epki_der);
    int rc = 0;

    ctx = OSSL_DECODER_CTX_new();
    if (dec == NULL || ctx == NULL)
        goto out;
    OSSL_DECODER_CTX_set_input_type(ctx, "DER");
    OSSL_DECODER_CTX_set_selection(ctx, EVP_PKEY_KEYPAIR);
    OSSL_DECODER_CTX_set_construct(ctx, decoder_construct);
    OSSL_DECODER_CTX_set_construct_data(ctx, (void *)key);
    if (OSSL_DECODER_CTX_add_decoder(ctx, dec) != 1)
        goto out;
    if (with_passphrase)
        OSSL_DECODER_CTX_set_passphrase(ctx, (const unsigned char *)"12345", 5);

    /* Only the decode's own errors are observed. */
    ERR_clear_error();
    rc = OSSL_DECODER_from_data(ctx, &p, &len);
    kv_int("dec.from_data", rc);
    errs(key);

out:
    OSSL_DECODER_CTX_free(ctx);
    OSSL_DECODER_free(dec);
}

/* Join 2: the decrypt arm over the published vector. */
static void arm_decoder_decode(void)
{
    decoder_run("dec.encrypted", 1);
}

/* Join 3: the passphrase refusal. Without a passphrase the framework's callback refuses and the
 * engine raises PROV_R_UNABLE_TO_GET_PASSPHRASE at its own coordinate. */
static void arm_decoder_refusal(void)
{
    decoder_run("dec.no_passphrase", 0);
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

/* ===========================================================================
 * The sixty-nine `decode_der2key.c` rows -- this unit's whole table set -- and
 * `decode_epki2pki.c`'s one `EncryptedPrivateKeyInfo` row, which `decoders.inc`
 * places in the same combined provider table.
 *
 * Join 1: **identity for all seventy rows, in both providers** (140 fetches), the same
 * shape the text and blob arms use: fetch each row by its own name with an
 * `input=der,structure=<s>` query and read `get0_name`/`get0_properties` back through the
 * fetched object. That is the join that observes a row's published identity rather than
 * its bytes (docs/PHASE-10-SUBPHASES.md section 3.1).
 *
 * Join 2: **behaviour** where the row's key type is landable from a *fixed published input*
 * the authority's own tree carries:
 *   - the four ECX types, each from the `test/recipes/30-test_evp_data/evppkey_ecx.txt`
 *     PKCS#8 and SPKI bodies (test vector 1: `Alice-25519`, `Alice-448`, `ED25519-1`,
 *     `ED448-1`), driven through `OSSL_DECODER_CTX_new_for_pkey` so both the
 *     `PrivateKeyInfo` and the `SubjectPublicKeyInfo` row answer;
 *   - the `DH`/`DHX` parameter rows from the `test/recipes/20-test_dhparam_data` PKCS#3
 *     (`pkcs3-2-1024.der`, `pkcs3-5-1024.der`) and X9.42 (`x942-0-1024.der`) bodies.
 * Each prints the constructed object's type, bit length and public key, so the private half
 * is observed to have produced the right public half rather than merely to have parsed --
 * the round trip is not the claim.
 *
 * Join 3: the row's own refusals, with their coordinates -- the selection refusal
 * (`decode_der2key.c:300`, `ERR_R_PASSED_INVALID_ARGUMENT`) and the SLH-DSA
 * `SubjectPublicKeyInfo` length check (`:751`, `PROV_R_BAD_ENCODING`) for all twelve
 * SLH-DSA rows.
 *
 * ## What is identity-only, and why (docs/PHASE-10-SUBPHASES.md section 3.5)
 *
 * A row that no arm can drive is named `pending` rather than counted as passing. Two
 * measured reasons cover the rest:
 *
 *   - `no-fixed-der`: `RSA`/`RSA-PSS`/`DSA` and every `type-specific`/`dsa`/`rsa`/`ec`
 *     structure need a full private key, modulus or parameter body, and the authority's own
 *     tree carries no bare `.der` for any of them;
 *   - `encoder-unlanded`: the `EC`/`SM2` `PrivateKeyInfo`/`SubjectPublicKeyInfo` bodies and
 *     all eighteen PQC bodies need a fixed DER an *encoder* would write, and their writer,
 *     `encode_key2any.c`, is not landed.
 *
 * The `decoder.pending.*` lines below are printed per row per provider so that "not
 * driven" cannot be read as "passed".
 * ========================================================================= */

struct decoder_row {
    const char *name;
    const char *structure;
    /* NULL when an arm drives the row; otherwise the measured reason it is `pending`. */
    const char *pending;
};

/* The seventy rows in `decoders.inc`'s order: `decode_der2key.c`'s sixty-nine tables
 * (the classic types, the PQC rows, `RSA`/`RSA-PSS`/`ML-DSA`, then the twelve SLH-DSA
 * pairs), then `decode_epki2pki.c`'s one `EncryptedPrivateKeyInfo` row. */
static const struct decoder_row decoder_rows[] = {
    { "DH", "PrivateKeyInfo", "no-fixed-der" },
    { "DH", "SubjectPublicKeyInfo", "no-fixed-der" },
    { "DH", "type-specific", NULL },
    { "DH", "dh", NULL },
    { "DHX", "PrivateKeyInfo", "no-fixed-der" },
    { "DHX", "SubjectPublicKeyInfo", "no-fixed-der" },
    { "DHX", "type-specific", NULL },
    { "DHX", "dhx", NULL },
    { "DSA", "PrivateKeyInfo", "no-fixed-der" },
    { "DSA", "SubjectPublicKeyInfo", "no-fixed-der" },
    { "DSA", "type-specific", "no-fixed-der" },
    { "DSA", "dsa", "no-fixed-der" },
    { "EC", "PrivateKeyInfo", "encoder-unlanded" },
    { "EC", "SubjectPublicKeyInfo", "encoder-unlanded" },
    { "EC", "type-specific", "no-fixed-der" },
    { "EC", "ec", "no-fixed-der" },
    { "ED25519", "PrivateKeyInfo", NULL },
    { "ED25519", "SubjectPublicKeyInfo", NULL },
    { "ED448", "PrivateKeyInfo", NULL },
    { "ED448", "SubjectPublicKeyInfo", NULL },
    { "X25519", "PrivateKeyInfo", NULL },
    { "X25519", "SubjectPublicKeyInfo", NULL },
    { "X448", "PrivateKeyInfo", NULL },
    { "X448", "SubjectPublicKeyInfo", NULL },
    { "SM2", "PrivateKeyInfo", "encoder-unlanded" },
    { "SM2", "SubjectPublicKeyInfo", "encoder-unlanded" },
    { "SM2", "type-specific", "no-fixed-der" },
    { "ML-KEM-512", "PrivateKeyInfo", "encoder-unlanded" },
    { "ML-KEM-512", "SubjectPublicKeyInfo", "encoder-unlanded" },
    { "ML-KEM-768", "PrivateKeyInfo", "encoder-unlanded" },
    { "ML-KEM-768", "SubjectPublicKeyInfo", "encoder-unlanded" },
    { "ML-KEM-1024", "PrivateKeyInfo", "encoder-unlanded" },
    { "ML-KEM-1024", "SubjectPublicKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHA2-128s", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHA2-128f", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHA2-192s", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHA2-192f", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHA2-256s", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHA2-256f", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHAKE-128s", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHAKE-128f", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHAKE-192s", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHAKE-192f", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHAKE-256s", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHAKE-256f", "PrivateKeyInfo", "encoder-unlanded" },
    { "SLH-DSA-SHA2-128s", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHA2-128f", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHA2-192s", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHA2-192f", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHA2-256s", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHA2-256f", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHAKE-128s", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHAKE-128f", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHAKE-192s", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHAKE-192f", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHAKE-256s", "SubjectPublicKeyInfo", NULL },
    { "SLH-DSA-SHAKE-256f", "SubjectPublicKeyInfo", NULL },
    { "RSA", "PrivateKeyInfo", "no-fixed-der" },
    { "RSA", "SubjectPublicKeyInfo", "no-fixed-der" },
    { "RSA", "type-specific", "no-fixed-der" },
    { "RSA", "rsa", "no-fixed-der" },
    { "RSA-PSS", "PrivateKeyInfo", "no-fixed-der" },
    { "RSA-PSS", "SubjectPublicKeyInfo", "no-fixed-der" },
    { "ML-DSA-44", "PrivateKeyInfo", "encoder-unlanded" },
    { "ML-DSA-65", "PrivateKeyInfo", "encoder-unlanded" },
    { "ML-DSA-87", "PrivateKeyInfo", "encoder-unlanded" },
    { "ML-DSA-44", "SubjectPublicKeyInfo", "encoder-unlanded" },
    { "ML-DSA-65", "SubjectPublicKeyInfo", "encoder-unlanded" },
    { "ML-DSA-87", "SubjectPublicKeyInfo", "encoder-unlanded" },
    { "DER", "EncryptedPrivateKeyInfo", NULL }
};

/* Join 1: every row's identity through the provider that publishes it, and the `pending`
 * name for each row no arm drives. */
static void arm_decoder_identity_all(void)
{
    size_t i, j;

    for (j = 0; j < sizeof(providers) / sizeof(providers[0]); j++) {
        for (i = 0; i < sizeof(decoder_rows) / sizeof(decoder_rows[0]); i++) {
            char prop[96], key[160];
            OSSL_DECODER *dec;

            snprintf(prop, sizeof(prop), "provider=%s,input=der,structure=%s",
                     providers[j], decoder_rows[i].structure);
            dec = OSSL_DECODER_fetch(NULL, decoder_rows[i].name, prop);
            kv_int("decoder.fetch", dec != NULL);
            if (dec != NULL) {
                kv_str("decoder.name", OSSL_DECODER_get0_name(dec));
                kv_str("decoder.props", OSSL_DECODER_get0_properties(dec));
                kv_int("decoder.is_a_self",
                       OSSL_DECODER_is_a(dec, decoder_rows[i].name));
                kv_int("decoder.is_a_der", OSSL_DECODER_is_a(dec, "DER"));
            }
            OSSL_DECODER_free(dec);

            if (decoder_rows[i].pending != NULL) {
                snprintf(key, sizeof(key), "decoder.pending.%s.%s.%s", providers[j],
                         decoder_rows[i].name, decoder_rows[i].structure);
                kv_str(key, decoder_rows[i].pending);
            }
        }
        ERR_clear_error();
    }
}

/* The four ECX types' fixed published bodies: `evppkey_ecx.txt` test vector 1's PKCS#8
 * private keys and SubjectPublicKeyInfo public keys (RFC 7748's and RFC 8032's own). */
static const unsigned char x25519_priv[48] = {
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
    0x04, 0x22, 0x04, 0x20, 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87,
    0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
};
static const unsigned char x25519_spki[44] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc,
    0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
};
static const unsigned char x448_priv[72] = {
    0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f,
    0x04, 0x3a, 0x04, 0x38, 0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
    0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4, 0xee, 0x9e, 0xe8, 0xba,
    0xe8, 0xbc, 0x55, 0x65, 0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
    0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91, 0x00, 0x63, 0x82, 0xa6,
    0xf1, 0x27, 0xab, 0x1d, 0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
};
static const unsigned char x448_spki[68] = {
    0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39, 0x00,
    0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6, 0x7d, 0x22, 0xd5, 0xae,
    0xa1, 0x21, 0x07, 0x4a, 0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
    0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb, 0xc8, 0x36, 0x64, 0x72,
    0x41, 0xd9, 0x53, 0xd4, 0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
    0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
};
static const unsigned char ed25519_priv[48] = {
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20, 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69,
    0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};
static const unsigned char ed25519_spki[44] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
    0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};
static const unsigned char ed448_priv[73] = {
    0x30, 0x47, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71,
    0x04, 0x3b, 0x04, 0x39, 0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10,
    0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf, 0x6c, 0x92, 0x9f, 0x34,
    0xdd, 0xfa, 0x8c, 0x9f, 0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3,
    0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e, 0x39, 0xa3, 0xfc, 0x5b,
    0x94, 0x49, 0x2f, 0x8f, 0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9,
    0x5b,
};
static const unsigned char ed448_spki[69] = {
    0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00,
    0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd, 0x2c, 0xe7, 0x87, 0xec,
    0x61, 0x6a, 0xd4, 0x6a, 0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f,
    0x8a, 0x0e, 0xa7, 0x5d, 0x80, 0xe9, 0x67, 0x78, 0xed, 0xf1, 0x24, 0x76,
    0x9b, 0x46, 0xc7, 0x06, 0x1b, 0xd6, 0x78, 0x3d, 0xf1, 0xe5, 0x0f, 0x6c,
    0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61, 0x80,
};

/* The DH/DHX parameter bodies: `20-test_dhparam_data`'s PKCS#3 (generator 2 and 5) and
 * X9.42 bodies. They drive the `DH`/`DHX` `type-specific` and `dh`/`dhx` rows. */
static const unsigned char pkcs3_2_1024[138] = {
    0x30, 0x81, 0x87, 0x02, 0x81, 0x81, 0x00, 0x84, 0x18, 0xaa, 0x5d, 0xaa,
    0x31, 0x67, 0x0b, 0x2e, 0x53, 0x65, 0x5d, 0x17, 0xcc, 0x12, 0x7c, 0x10,
    0x45, 0x75, 0x16, 0xf0, 0x60, 0xbf, 0xce, 0x8f, 0x9b, 0x3f, 0xf9, 0x9d,
    0x1c, 0x18, 0x8a, 0xec, 0x71, 0x70, 0x5f, 0x40, 0x4a, 0x2b, 0x70, 0xda,
    0x4c, 0x2e, 0x18, 0x43, 0x87, 0x70, 0xba, 0x96, 0xd3, 0x03, 0x2a, 0x9f,
    0xaf, 0x0a, 0xfb, 0x21, 0x74, 0x45, 0x26, 0x2e, 0x0f, 0x44, 0x23, 0x3f,
    0xed, 0xac, 0x3d, 0xd6, 0xd1, 0xf2, 0x22, 0x1c, 0xa6, 0xc6, 0x47, 0x19,
    0x47, 0x87, 0x73, 0x59, 0xed, 0xcd, 0x9a, 0xc2, 0x80, 0x7e, 0xf8, 0x8c,
    0x0e, 0x3e, 0x9d, 0x15, 0x57, 0x0a, 0x31, 0xdd, 0x72, 0xc4, 0x24, 0xeb,
    0xb7, 0xb1, 0x27, 0xd3, 0xbd, 0x61, 0xde, 0x18, 0xcf, 0xa7, 0xa6, 0x31,
    0x6a, 0x89, 0xb9, 0x21, 0x82, 0xad, 0x16, 0x11, 0xdc, 0xb1, 0x57, 0x6a,
    0xfe, 0xec, 0x03, 0x02, 0x01, 0x02,
};
static const unsigned char pkcs3_5_1024[138] = {
    0x30, 0x81, 0x87, 0x02, 0x81, 0x81, 0x00, 0xcc, 0xb0, 0x83, 0x8b, 0x64,
    0xd1, 0x7e, 0x16, 0x1e, 0xee, 0x84, 0x57, 0xdc, 0x37, 0xac, 0xfc, 0x0f,
    0x89, 0x30, 0xb6, 0x49, 0x0f, 0x2e, 0xfa, 0x60, 0x30, 0x4f, 0x42, 0xe5,
    0x09, 0x4e, 0xc6, 0x40, 0xc1, 0xdb, 0x66, 0x2f, 0x0f, 0x7b, 0x18, 0xd7,
    0x21, 0xb0, 0x02, 0x3d, 0xfa, 0x9d, 0x1d, 0x6e, 0xbd, 0xe2, 0x25, 0xf1,
    0x8f, 0x73, 0x7b, 0xff, 0xab, 0x73, 0x6f, 0x4b, 0x46, 0xe8, 0x9d, 0xb0,
    0x3b, 0x96, 0xb3, 0x45, 0x83, 0xd9, 0xbf, 0xfe, 0x7e, 0xdf, 0x9c, 0x45,
    0x00, 0x37, 0xe2, 0x52, 0xca, 0x65, 0xe9, 0xfc, 0x66, 0xbc, 0x48, 0xdc,
    0x2a, 0xed, 0x2d, 0xa1, 0xe9, 0xdf, 0x46, 0x50, 0x3e, 0xe9, 0xdf, 0xba,
    0x97, 0x11, 0x72, 0xab, 0xf2, 0xc6, 0xd1, 0xd2, 0xb3, 0xbd, 0x82, 0x6e,
    0x84, 0xf3, 0xf8, 0x70, 0xef, 0xe7, 0x36, 0x1e, 0xee, 0x4d, 0x80, 0x1c,
    0x8d, 0x2f, 0xaf, 0x02, 0x01, 0x05,
};
static const unsigned char x942_0_1024[319] = {
    0x30, 0x82, 0x01, 0x3b, 0x02, 0x81, 0x81, 0x00, 0xd9, 0x3a, 0xda, 0x88,
    0x04, 0x1d, 0xfb, 0x1b, 0xbd, 0xb2, 0x00, 0x23, 0x19, 0x61, 0x2d, 0x6f,
    0xe3, 0x2d, 0xf4, 0x01, 0x15, 0x7b, 0x3a, 0xa3, 0xc5, 0x93, 0x90, 0xd8,
    0x2d, 0x11, 0xc3, 0x2a, 0x12, 0x5d, 0x65, 0xb1, 0xc9, 0x3a, 0x9d, 0x48,
    0x2f, 0xed, 0x58, 0x3e, 0x99, 0xbc, 0x16, 0x6d, 0x68, 0x95, 0x86, 0x9c,
    0x6b, 0x27, 0x3f, 0x18, 0x98, 0x45, 0xcd, 0xe4, 0xac, 0x0d, 0x6f, 0xc6,
    0x38, 0x49, 0x26, 0x2d, 0x28, 0x45, 0x34, 0x4c, 0x64, 0x7c, 0xf1, 0xa9,
    0x47, 0x65, 0x7e, 0x76, 0xf0, 0x7c, 0x40, 0xea, 0x7f, 0x58, 0x19, 0xe7,
    0x19, 0x33, 0x5f, 0xa2, 0xeb, 0x06, 0xfb, 0xf6, 0x37, 0xec, 0xd5, 0xd0,
    0xa6, 0x6b, 0x29, 0x55, 0x95, 0xae, 0x17, 0x6f, 0x6f, 0x0b, 0xf5, 0xb9,
    0x22, 0x68, 0x7c, 0xbb, 0x17, 0xb1, 0x47, 0x7e, 0xd1, 0x4c, 0xc5, 0x65,
    0x6d, 0xde, 0x19, 0x2b, 0x02, 0x81, 0x80, 0x3a, 0x6e, 0x64, 0x58, 0x79,
    0x1e, 0x80, 0xe0, 0xae, 0xa0, 0x78, 0xcb, 0xfa, 0x30, 0xcc, 0x6e, 0xaf,
    0x16, 0x28, 0xcd, 0x4b, 0x0f, 0x49, 0x40, 0x3f, 0x22, 0x84, 0xed, 0x31,
    0xd8, 0x84, 0xdb, 0xfd, 0xba, 0x75, 0xbc, 0xe2, 0x47, 0xea, 0xcb, 0x5e,
    0x70, 0x2a, 0x96, 0x21, 0x35, 0xc7, 0xd1, 0x5c, 0x89, 0x6f, 0xe5, 0xf3,
    0x51, 0x04, 0x04, 0xd4, 0x19, 0x3a, 0x49, 0x95, 0xed, 0x87, 0x79, 0x46,
    0x37, 0xbe, 0xc6, 0xb7, 0xe6, 0xc8, 0xdc, 0x1b, 0x9b, 0x37, 0xd8, 0xa4,
    0x9f, 0x51, 0x5b, 0x87, 0x6e, 0xbb, 0x7c, 0x0d, 0xd1, 0xfa, 0x75, 0x65,
    0x45, 0x9c, 0xce, 0x05, 0xf1, 0xd3, 0xc2, 0xe3, 0x69, 0xc3, 0x89, 0xbb,
    0x04, 0xe4, 0x4e, 0x5b, 0xf5, 0xbd, 0xf6, 0x3c, 0xb7, 0xd1, 0x6b, 0xd7,
    0x58, 0xd3, 0xb7, 0x99, 0x53, 0x13, 0x09, 0x3e, 0xd7, 0xe7, 0x1a, 0x93,
    0x09, 0xad, 0x7b, 0x02, 0x15, 0x00, 0x88, 0x54, 0xe7, 0x97, 0x2f, 0x7b,
    0xc5, 0x42, 0xdb, 0x91, 0xcd, 0x8c, 0x68, 0x0d, 0x06, 0x26, 0x57, 0x23,
    0xe2, 0x65, 0x30, 0x1b, 0x03, 0x15, 0x00, 0xad, 0xe6, 0xea, 0xb6, 0xe7,
    0x9e, 0xfe, 0xfa, 0xa9, 0x46, 0x4b, 0x8c, 0xa5, 0x06, 0x66, 0xbb, 0x15,
    0xbc, 0xfb, 0xeb, 0x02, 0x02, 0x01, 0x03,
};

/* Decode `der` with the framework's own pkey context: it collects the decoders that answer
 * `type` at `selection` and drives whichever row matches the input, so the transcript
 * observes the row and the selection filter together. The constructed object's type, bit
 * length and public key are printed so the private half is seen to yield the right public
 * half. */
static void decoder_build(const char *key, const char *type, int selection,
                          const unsigned char *der, size_t derlen)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, type,
                                                          selection, NULL, NULL);
    const unsigned char *p = der;
    size_t len = derlen;
    unsigned char out[96];
    size_t outlen = 0;
    int rc;

    ERR_clear_error();
    rc = ctx == NULL ? -1 : OSSL_DECODER_from_data(ctx, &p, &len);
    kv_int("decoder.from_data", rc);
    if (pkey != NULL) {
        kv_str("decoder.type", EVP_PKEY_get0_type_name(pkey));
        kv_int("decoder.bits", EVP_PKEY_get_bits(pkey));
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out,
                                            sizeof(out), &outlen) == 1)
            kv_hex(key, out, outlen);
    }
    errs(key);
    EVP_PKEY_free(pkey);
    OSSL_DECODER_CTX_free(ctx);
}

/* Join 2: the four ECX types, each decoded from its fixed PKCS#8 (the PrivateKeyInfo row)
 * and its fixed SubjectPublicKeyInfo (the SPKI row). */
static void arm_decoder_ecx(void)
{
    static const struct {
        const char *type;
        const unsigned char *priv;
        size_t privlen;
        const unsigned char *spki;
        size_t spkilen;
    } rows[] = {
        { "X25519", x25519_priv, sizeof(x25519_priv), x25519_spki, sizeof(x25519_spki) },
        { "X448", x448_priv, sizeof(x448_priv), x448_spki, sizeof(x448_spki) },
        { "ED25519", ed25519_priv, sizeof(ed25519_priv), ed25519_spki,
          sizeof(ed25519_spki) },
        { "ED448", ed448_priv, sizeof(ed448_priv), ed448_spki, sizeof(ed448_spki) }
    };
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        char key[64];

        snprintf(key, sizeof(key), "decoder.ecx.%s.p8", rows[i].type);
        decoder_build(key, rows[i].type, EVP_PKEY_KEYPAIR, rows[i].priv, rows[i].privlen);
        snprintf(key, sizeof(key), "decoder.ecx.%s.spki", rows[i].type);
        decoder_build(key, rows[i].type, EVP_PKEY_PUBLIC_KEY, rows[i].spki, rows[i].spkilen);
    }
}

/* Join 2: the `DH`/`DHX` parameter rows, decoded from the fixed PKCS#3 and X9.42 bodies. */
static void arm_decoder_dh_params(void)
{
    decoder_build("decoder.dh.pkcs3_2_1024", "DH", EVP_PKEY_KEY_PARAMETERS, pkcs3_2_1024,
                  sizeof(pkcs3_2_1024));
    decoder_build("decoder.dh.pkcs3_5_1024", "DH", EVP_PKEY_KEY_PARAMETERS, pkcs3_5_1024,
                  sizeof(pkcs3_5_1024));
    decoder_build("decoder.dhx.x942_0_1024", "DHX", EVP_PKEY_KEY_PARAMETERS, x942_0_1024,
                  sizeof(x942_0_1024));
}

/* Join 3: the selection refusal. The `X25519` `SubjectPublicKeyInfo` row's description
 * supports only the public-key bit, so a context that adds the row directly and asks it for
 * a private-key selection is refused by the engine's own check -- `decode_der2key.c:300`,
 * `ERR_R_PASSED_INVALID_ARGUMENT` -- rather than filtered out at collect time. */
static void arm_decoder_selection_refusal(void)
{
    OSSL_DECODER *dec = OSSL_DECODER_fetch(NULL, "X25519",
        "provider=default,input=der,structure=SubjectPublicKeyInfo");
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new();
    const unsigned char *p = x25519_spki;
    size_t len = sizeof(x25519_spki);
    int rc = 0;

    if (dec == NULL || ctx == NULL)
        goto out;
    OSSL_DECODER_CTX_set_input_type(ctx, "DER");
    OSSL_DECODER_CTX_set_selection(ctx, EVP_PKEY_PRIVATE_KEY);
    if (OSSL_DECODER_CTX_add_decoder(ctx, dec) != 1)
        goto out;

    ERR_clear_error();
    rc = OSSL_DECODER_from_data(ctx, &p, &len);
    kv_int("decoder.selection_refusal", rc);
    errs("decoder.selection_refusal");

out:
    OSSL_DECODER_CTX_free(ctx);
    OSSL_DECODER_free(dec);
}

/* The twelve SLH-DSA key type names, in `decoders.inc`'s order. */
static const char *const slh_dsa_names[] = {
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
};

/* Join 3: the SLH-DSA `SubjectPublicKeyInfo` rows over a five-byte body. Each row's decode
 * runs and yields no key, and the framework answers with its own `No supported data to
 * decode` (`decoder_lib.c:104`) -- the row's internal, non-fatal refusal is discarded by the
 * framework's `ERR_pop_to_mark`, so the observable answer is the framework's and the
 * coordinate is named rather than claimed. The arm still drives all twelve rows. */
static void arm_decoder_slh_length_refusal(void)
{
    static const unsigned char short_body[5] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    size_t i;

    for (i = 0; i < sizeof(slh_dsa_names) / sizeof(slh_dsa_names[0]); i++) {
        OSSL_DECODER *dec = OSSL_DECODER_fetch(NULL, slh_dsa_names[i],
            "provider=default,input=der,structure=SubjectPublicKeyInfo");
        OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new();
        const unsigned char *p = short_body;
        size_t len = sizeof(short_body);
        int rc = 0;

        if (dec == NULL || ctx == NULL)
            goto out;
        OSSL_DECODER_CTX_set_input_type(ctx, "DER");
        OSSL_DECODER_CTX_set_selection(ctx, EVP_PKEY_PUBLIC_KEY);
        if (OSSL_DECODER_CTX_add_decoder(ctx, dec) != 1)
            goto out;

        ERR_clear_error();
        rc = OSSL_DECODER_from_data(ctx, &p, &len);
        kv_int("decoder.slh_length_refusal", rc);
        errs("decoder.slh_length_refusal");

out:
        OSSL_DECODER_CTX_free(ctx);
        OSSL_DECODER_free(dec);
    }
}

/* ---------------------------------------------------------------------------
 * The eighteen PQC text rows, and the printers behind them.
 *
 * The three codec helper units this slice lands (`ml_common_codecs.c`, `ml_kem_codecs.c`,
 * `ml_dsa_codecs.c`) and `slh_dsa_key.c`'s tail publish no provider row of their own; they are
 * observed here through the three text encoders that call their `*_to_text` printers. Their
 * d2i/i2d half is now reached by `decode_der2key.c`, which landed with this slice and whose
 * rows the decoder arms above drive; `encode_key2any.c` is the remaining writer and is not.
 *
 * Join 2: a keypair built from a fixed input, encoded as text. Nothing is generated from a random
 * value: ML-KEM's and ML-DSA's keygen seeds and SLH-DSA's full private keys are the constants
 * Phase 8's courts already carry.
 * ------------------------------------------------------------------------- */

/* A keypair generated deterministically from a fixed `seed` generation parameter, or NULL. */
static EVP_PKEY *seed_key(const char *type, const char *seed_param,
    const unsigned char *seed, size_t seedlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    OSSL_PARAM params[2];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) != 1)
        goto out;
    params[0] = OSSL_PARAM_construct_octet_string(seed_param, (void *)seed, seedlen);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
        goto out;
    (void)EVP_PKEY_generate(ctx, &pkey);
out:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* A key built by importing a fixed private key (`OSSL_PKEY_PARAM_PRIV_KEY`), or NULL. */
static EVP_PKEY *priv_key(const char *type, const unsigned char *priv, size_t privlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    OSSL_PARAM params[2];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_fromdata_init(ctx) != 1)
        goto out;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)priv, privlen);
    params[1] = OSSL_PARAM_construct_end();
    (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
out:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* A public-only key built by importing fixed public bytes, or NULL. */
static EVP_PKEY *pub_key(const char *type, const unsigned char *pub, size_t publen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    OSSL_PARAM params[2];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_fromdata_init(ctx) != 1)
        goto out;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, publen);
    params[1] = OSSL_PARAM_construct_end();
    (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
out:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Join 2: every PQC text row over a fixed keypair, KEYPAIR selection. */
static void arm_pqc_text(void)
{
    size_t i;
    char key[96];

    for (i = 0; i < sizeof(ml_kem_kat_rows) / sizeof(ml_kem_kat_rows[0]); i++) {
        const struct ml_kem_probe_row *r = &ml_kem_kat_rows[i];
        EVP_PKEY *pkey = seed_key(r->name, OSSL_PKEY_PARAM_ML_KEM_SEED, r->seed, r->seedlen);

        snprintf(key, sizeof(key), "codec.pqc_mlkem.%s.keypair", r->name);
        kv_int("codec.pqc.built", pkey != NULL);
        if (pkey != NULL)
            encode_and_report(key, pkey, EVP_PKEY_KEYPAIR);
        EVP_PKEY_free(pkey);
    }

    {
        static const char *names[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };

        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            EVP_PKEY *pkey = seed_key(names[i], OSSL_PKEY_PARAM_ML_DSA_SEED,
                                      ml_dsa_seed, sizeof(ml_dsa_seed));

            snprintf(key, sizeof(key), "codec.pqc_mldsa.%s.keypair", names[i]);
            kv_int("codec.pqc.built", pkey != NULL);
            if (pkey != NULL)
                encode_and_report(key, pkey, EVP_PKEY_KEYPAIR);
            EVP_PKEY_free(pkey);
        }
    }

    for (i = 0; i < sizeof(slh_dsa_rows) / sizeof(slh_dsa_rows[0]); i++) {
        EVP_PKEY *pkey = priv_key(slh_dsa_rows[i].name, slh_dsa_rows[i].key, slh_dsa_rows[i].len);

        snprintf(key, sizeof(key), "codec.pqc_slhdsa.%s.keypair", slh_dsa_rows[i].name);
        kv_int("codec.pqc.built", pkey != NULL);
        if (pkey != NULL)
            encode_and_report(key, pkey, EVP_PKEY_KEYPAIR);
        EVP_PKEY_free(pkey);
    }
}

/* Join 3: the two printers' selection refusals, both `PROV_R_MISSING_KEY`.
 *
 * ML-DSA's printer raises when the private-key bit is set and there is no private key (`:432`);
 * SLH-DSA's does the same (`:507`). Both are driven by a public-only key asked for a keypair. */
static void arm_pqc_refusals(void)
{
    EVP_PKEY *pkey = seed_key("ML-DSA-44", OSSL_PKEY_PARAM_ML_DSA_SEED,
                              ml_dsa_seed, sizeof(ml_dsa_seed));

    /* ML-DSA-44: derive a keypair from the seed, extract its public key, then import it alone. */
    if (pkey != NULL) {
        unsigned char pub[1600];
        size_t publen = 0;

        kv_int("codec.pqc.refusal.pub",
               EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub),
                                               &publen));
        EVP_PKEY_free(pkey);
        if (publen > 0) {
            EVP_PKEY *pubonly = pub_key("ML-DSA-44", pub, publen);

            kv_int("codec.pqc.refusal.pubonly", pubonly != NULL);
            if (pubonly != NULL)
                encode_and_report("codec.pqc_mldsa.refuse_private", pubonly, EVP_PKEY_KEYPAIR);
            EVP_PKEY_free(pubonly);
        }
    }

    /* SLH-DSA-SHA2-128s: the last 2n bytes of the vector are `PK_SEED || PK_ROOT`. */
    {
        size_t n = slh_dsa_rows[0].len / 4;
        EVP_PKEY *pubonly = pub_key(slh_dsa_rows[0].name, slh_dsa_rows[0].key + 2 * n, 2 * n);

        kv_int("codec.pqc.refusal.slh_pubonly", pubonly != NULL);
        if (pubonly != NULL)
            encode_and_report("codec.pqc_slhdsa.refuse_private", pubonly, EVP_PKEY_KEYPAIR);
        EVP_PKEY_free(pubonly);
    }
}

/* ===========================================================================
 * The MSBLOB and PVK rows `encode_key2ms.c` (four encoder rows) and
 * `decode_msblob2key.c`/`decode_pvk2key.c` (four decoder rows) publish, landed with 10.6.
 *
 * Join 1: identity for all eight encoder rows (four rows x two providers) with an
 * `output=msblob`/`output=pvk` query, and all eight decoder rows with `input=msblob`/
 * `input=pvk`. These rows carry no `structure=`, unlike the `DECODER_w_structure` rows
 * above (`decoders.inc:53-54`, `:117-118`).
 *
 * Join 2: **behaviour**, from the fixed RSA and DSA keypairs `rt_keyformat_keys.h` carries
 * (`rsa_pkcs8_der`, `dsa_pkcs8_der`), built through the `PrivateKeyInfo` decoders so no
 * legacy key is involved. Each is encoded to `msblob` and to `pvk` (the unencrypted level
 * 0, the one level that needs no legacy `RC4`/`PVKKDF`), and the exact bytes are printed.
 * Those same bytes are fed back to the matching decoder row and the reconstructed key's
 * bit length is printed, so the decoder's input is a function of the fixed key alone.
 *
 * Join 3: the refusals, with their coordinates. The encoder's `does_selection` refuses a
 * selection with neither key bit (`KEY_PARAMETERS`) and the `pvk` row's `encode` refuses a
 * public-only selection; the `msblob` decoder raises `PROV_R_BAD_ENCODING` on a body
 * shorter than its sixteen-byte header (`decode_msblob2key.c:111`).
 * ========================================================================= */

/* One row per `encoders.inc`/`decoders.inc` row `encode_key2ms.c` and the two decoder units
 * publish: the key type's name and the `msblob`/`pvk` output (the decoder's `input=`). */
static const struct {
    const char *name;
    const char *out;
} ms_rows[] = {
    { "RSA", "msblob" }, { "RSA", "pvk" }, { "DSA", "msblob" }, { "DSA", "pvk" }
};

static void arm_ms_identity(void)
{
    size_t i, j;

    for (j = 0; j < sizeof(providers) / sizeof(providers[0]); j++) {
        for (i = 0; i < sizeof(ms_rows) / sizeof(ms_rows[0]); i++) {
            char prop[80];
            OSSL_ENCODER *enc;
            OSSL_DECODER *dec;

            snprintf(prop, sizeof(prop), "provider=%s,output=%s", providers[j], ms_rows[i].out);
            enc = OSSL_ENCODER_fetch(NULL, ms_rows[i].name, prop);
            kv_int("ms.enc_fetch", enc != NULL);
            if (enc != NULL) {
                kv_str("ms.enc_name", OSSL_ENCODER_get0_name(enc));
                kv_str("ms.enc_props", OSSL_ENCODER_get0_properties(enc));
                kv_int("ms.enc_is_a_self", OSSL_ENCODER_is_a(enc, ms_rows[i].name));
                kv_int("ms.enc_is_a_out", OSSL_ENCODER_is_a(enc, ms_rows[i].out));
            }
            OSSL_ENCODER_free(enc);

            snprintf(prop, sizeof(prop), "provider=%s,input=%s", providers[j], ms_rows[i].out);
            dec = OSSL_DECODER_fetch(NULL, ms_rows[i].name, prop);
            kv_int("ms.dec_fetch", dec != NULL);
            if (dec != NULL) {
                kv_str("ms.dec_name", OSSL_DECODER_get0_name(dec));
                kv_str("ms.dec_props", OSSL_DECODER_get0_properties(dec));
                kv_int("ms.dec_is_a_self", OSSL_DECODER_is_a(dec, ms_rows[i].name));
            }
            OSSL_DECODER_free(dec);
        }
        ERR_clear_error();
    }
}

/* Build a provider keypair from a fixed PKCS#8 body, through the decoder rows 10.1 landed. */
static EVP_PKEY *ms_pkey_from_pkcs8(const char *type, const unsigned char *der, size_t derlen)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, type,
                                                          EVP_PKEY_KEYPAIR, NULL, NULL);
    const unsigned char *p = der;
    size_t len = derlen;

    if (ctx == NULL)
        return NULL;
    if (OSSL_DECODER_from_data(ctx, &p, &len) != 1) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    OSSL_DECODER_CTX_free(ctx);
    return pkey;
}

/* Encode `pkey` with the `msblob`/`pvk` rows, print the exact bytes, then feed those same
 * bytes to the decoder row and print the reconstructed key's bit length. */
static void ms_roundtrip(const char *type, const unsigned char *der, size_t derlen)
{
    static const char *outs[2] = { "msblob", "pvk" };
    EVP_PKEY *pkey = ms_pkey_from_pkcs8(type, der, derlen);
    size_t k;

    kv_int("ms.built", pkey != NULL);
    if (pkey == NULL)
        return;
    for (k = 0; k < sizeof(outs) / sizeof(outs[0]); k++) {
        OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR,
                                                               outs[k], NULL, NULL);
        unsigned char *data = NULL;
        size_t len = 0;
        char key[64];
        int rc;

        /* The provider `pvk` row's default encrypt level is 1, which needs a passphrase no
         * `OSSL_ENCODER_to_data` supplies; level 0 is the unencrypted form, the one whose bytes
         * are a function of the key alone (and the only one the legacy `RC4`/`PVKKDF` rows, still
         * open, are not needed for). */
        if (strcmp(outs[k], "pvk") == 0) {
            int level = 0;
            OSSL_PARAM params[2];

            params[0] = OSSL_PARAM_construct_int(OSSL_ENCODER_PARAM_ENCRYPT_LEVEL, &level);
            params[1] = OSSL_PARAM_construct_end();
            kv_int("ms.set_encrypt_level", OSSL_ENCODER_CTX_set_params(ectx, params));
        }

        ERR_clear_error();
        rc = OSSL_ENCODER_to_data(ectx, &data, &len);
        snprintf(key, sizeof(key), "ms.encode.%s.%s", type, outs[k]);
        kv_int("ms.to_data", rc);
        errs(key);
        OSSL_ENCODER_CTX_free(ectx);

        if (rc == 1 && data != NULL) {
            snprintf(key, sizeof(key), "ms.bytes.%s.%s", type, outs[k]);
            kv_hex(key, data, len);
            {
                EVP_PKEY *got = NULL;
                OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&got, outs[k], NULL, type,
                                                                       EVP_PKEY_KEYPAIR, NULL, NULL);
                const unsigned char *p = data;
                size_t l = len;

                snprintf(key, sizeof(key), "ms.decode.%s.%s", type, outs[k]);
                ERR_clear_error();
                if (dctx != NULL)
                    kv_int("ms.from_data", OSSL_DECODER_from_data(dctx, &p, &l));
                errs(key);
                OSSL_DECODER_CTX_free(dctx);
                if (got != NULL)
                    kv_int("ms.dec_bits", EVP_PKEY_get_bits(got));
                EVP_PKEY_free(got);
            }
        }
        OPENSSL_free(data);
    }
    EVP_PKEY_free(pkey);
}

/* Join 3: the refusal arms, each printing the return and the error queue. */
static void arm_ms_refusals(void)
{
    EVP_PKEY *pkey = ms_pkey_from_pkcs8("RSA", rsa_pkcs8_der, sizeof(rsa_pkcs8_der));

    kv_int("ms.refusal.built", pkey != NULL);

    if (pkey != NULL) {
        OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEY_PARAMETERS,
                                                               "msblob", NULL, NULL);
        unsigned char *data = NULL;
        size_t len = 0;

        ERR_clear_error();
        kv_int("ms.refusal.params_rc", OSSL_ENCODER_to_data(ectx, &data, &len));
        errs("ms.refusal.params");
        OPENSSL_free(data);
        OSSL_ENCODER_CTX_free(ectx);

        /* The `pvk` row's `encode` refuses a public-only selection (`encode_key2ms.c:161`). */
        ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY, "pvk", NULL, NULL);
        data = NULL;
        len = 0;
        ERR_clear_error();
        kv_int("ms.refusal.pvk_pub_rc", OSSL_ENCODER_to_data(ectx, &data, &len));
        errs("ms.refusal.pvk_pub");
        OPENSSL_free(data);
        OSSL_ENCODER_CTX_free(ectx);
    }

    /* The `msblob` decoder's short-header arm (`decode_msblob2key.c:111`). */
    {
        static const unsigned char tiny[4] = { 0x01, 0x02, 0x03, 0x04 };
        EVP_PKEY *got = NULL;
        OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&got, "msblob", NULL, "RSA",
                                                               EVP_PKEY_KEYPAIR, NULL, NULL);
        const unsigned char *p = tiny;
        size_t len = sizeof(tiny);

        ERR_clear_error();
        if (dctx != NULL)
            kv_int("ms.refusal.short_rc", OSSL_DECODER_from_data(dctx, &p, &len));
        errs("ms.refusal.short");
        OSSL_DECODER_CTX_free(dctx);
        EVP_PKEY_free(got);
    }

    EVP_PKEY_free(pkey);
    ERR_clear_error();
}

static void arm_ms(void)
{
    ms_roundtrip("RSA", rsa_pkcs8_der, sizeof(rsa_pkcs8_der));
    ms_roundtrip("DSA", dsa160_pkcs8_der, sizeof(dsa160_pkcs8_der));
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

    arm_pqc_text();
    arm_pqc_refusals();

    arm_blob_identity();
    arm_blob_public();
    arm_blob_refusal();

    arm_decoder_identity();
    arm_decoder_decode();
    arm_decoder_refusal();

    arm_decoder_identity_all();
    arm_decoder_ecx();
    arm_decoder_dh_params();
    arm_decoder_selection_refusal();
    arm_decoder_slh_length_refusal();

    arm_ms_identity();
    arm_ms();
    arm_ms_refusals();

    OSSL_PROVIDER_unload(base);
    OSSL_PROVIDER_unload(deflt);
    return 0;
}
