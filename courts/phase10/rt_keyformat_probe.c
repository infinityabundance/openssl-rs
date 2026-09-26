/*
 * RT-KEYFORMAT -- Phase 10.6's key-format hand-off court.
 *
 * The twenty-six `d2i_*`/`i2d_*`/`PEM_*`/`b2i_*`/`i2b_*` names phases 5 and 7 handed forward, in
 * the five authority units `docs/PHASE-10-SUBPHASES.md` section 1 names: `crypto/pem/pvkfmt.c`,
 * `crypto/pem/pem_pk8.c`, `crypto/asn1/i2d_evp.c`, `crypto/asn1/d2i_pr.c` and
 * `crypto/pem/pem_pkey.c`. It is compiled once against the admitted authority and once against the
 * candidate distribution shell, and the two transcripts are compared line by line.
 *
 * ## The evidence is bytes and an error coordinate (section 3.4)
 *
 * Each name's only visible output is bytes. So the probe builds a **fixed legacy key** -- RSA, DSA
 * and EC, from the DER constants `rt_keyformat_keys.h` carries, which were produced once by the
 * authority's own `openssl` and are read by both sides -- and prints
 *   * the exact encoding each `i2d`/`i2b`/`PEM_*` writer produces, as hex, and
 *   * for each malformed-input arm, the return value and the error queue's lib/reason pairs.
 * A constant both sides read is the input, not the expectation.
 *
 * ## Both arms of the private-key readers are driven (section 3.4)
 *
 * `d2i_PrivateKey*`/`d2i_AutoPrivateKey*` try `d2i_PrivateKey_decoder` first and fall back to
 * `ossl_d2i_PrivateKey_legacy`. The probe therefore feeds each reader a PKCS#8 `PrivateKeyInfo`
 * (the decoder's arm), a bare PKCS#1/SEC1/DSA traditional body (the structure the decoder is asked
 * for as `type-specific`), and a truncated body, and prints the returned key's id and bits plus
 * the error queue. Which arm answered is a property of the implementation, and the transcript
 * records it for both.
 *
 * ## What is held pending, and why
 *
 * The encrypted PVK arm (`b2i_*_PVK_bio` over a salted body) needs the `legacy` provider's
 * `PVKKDF`/`RC4` rows, which are not landed; the probe drives the unencrypted level. The two
 * `i2d_PKCS8PrivateKey_nid_*` writers are held pending entirely (`do_pk8pkey`'s legacy encrypted
 * arm needs `PKCS8_encrypt`, 10.4's and open); their **addresses** are taken in `arm_reference`,
 * which claims they are non-NULL and nothing more.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

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

/* The error queue, normalised to the two portable fields. */
static void errs(const char *key)
{
    unsigned long e;
    int i = 0;

    while ((e = ERR_get_error()) != 0)
        printf("%s.%d=lib=%d,reason=%d\n", key, i++, ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("%s.count=%d\n", key, i);
}

/* --------------------------------------------------------------------------------------------
 * The legacy keys, built from the fixed DERs through the phase-8 readers (never through a 10.6
 * export, so the encode arms are not entangled with the reader arms).
 * ------------------------------------------------------------------------------------------ */

static EVP_PKEY *legacy_rsa(void)
{
    const unsigned char *p = rsa_pkcs1_der;
    RSA *k = d2i_RSAPrivateKey(NULL, &p, (long)sizeof(rsa_pkcs1_der));
    EVP_PKEY *pk;

    if (k == NULL)
        return NULL;
    pk = EVP_PKEY_new();
    if (pk == NULL || EVP_PKEY_set1_RSA(pk, k) != 1) {
        EVP_PKEY_free(pk);
        pk = NULL;
    }
    RSA_free(k);
    return pk;
}

static EVP_PKEY *legacy_dsa(void)
{
    const unsigned char *p = dsa_trad_der;
    DSA *k = d2i_DSAPrivateKey(NULL, &p, (long)sizeof(dsa_trad_der));
    EVP_PKEY *pk;

    if (k == NULL)
        return NULL;
    pk = EVP_PKEY_new();
    if (pk == NULL || EVP_PKEY_set1_DSA(pk, k) != 1) {
        EVP_PKEY_free(pk);
        pk = NULL;
    }
    DSA_free(k);
    return pk;
}

static EVP_PKEY *legacy_ec(void)
{
    /* Built from the P-256 group and a fixed scalar rather than read through `d2i_ECPrivateKey`,
     * so the encode arms do not depend on that reader and the public point is derived identically
     * on both sides. */
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *d = NULL;
    EC_POINT *pub = NULL;
    EVP_PKEY *pk = NULL;

    if (k == NULL)
        return NULL;
    if (BN_hex2bn(&d, "7d2e3f4a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f506") == 0)
        goto out;
    pub = EC_POINT_new(EC_KEY_get0_group(k));
    if (pub == NULL)
        goto out;
    if (EC_POINT_mul(EC_KEY_get0_group(k), pub, d, NULL, NULL, NULL) != 1)
        goto out;
    if (EC_KEY_set_private_key(k, d) != 1 || EC_KEY_set_public_key(k, pub) != 1)
        goto out;
    pk = EVP_PKEY_new();
    if (pk == NULL || EVP_PKEY_set1_EC_KEY(pk, k) != 1) {
        EVP_PKEY_free(pk);
        pk = NULL;
    }
out:
    EC_POINT_free(pub);
    BN_free(d);
    EC_KEY_free(k);
    return pk;
}

static void describe(const char *key, EVP_PKEY *pk)
{
    char k[160];

    kv_int(key, pk != NULL);
    if (pk != NULL) {
        snprintf(k, sizeof(k), "%s.is_a_rsa", key);
        kv_int(k, EVP_PKEY_is_a(pk, "RSA"));
        snprintf(k, sizeof(k), "%s.is_a_dsa", key);
        kv_int(k, EVP_PKEY_is_a(pk, "DSA"));
        snprintf(k, sizeof(k), "%s.is_a_ec", key);
        kv_int(k, EVP_PKEY_is_a(pk, "EC"));
        snprintf(k, sizeof(k), "%s.bits", key);
        kv_int(k, EVP_PKEY_get_bits(pk));
    }
}

/* --------------------------------------------------------------------------------------------
 * arm_reference -- all twenty-six names are defined by the linked library. For the twenty-four
 * that are driven below this is a floor; for the two `_nid_` writers it is the whole claim.
 * ------------------------------------------------------------------------------------------ */

static void arm_reference(void)
{
    volatile const void *v;

    v = (const void *)b2i_PVK_bio;        kv_int("ref.b2i_PVK_bio", v != NULL);
    v = (const void *)b2i_PVK_bio_ex;     kv_int("ref.b2i_PVK_bio_ex", v != NULL);
    v = (const void *)b2i_PrivateKey;     kv_int("ref.b2i_PrivateKey", v != NULL);
    v = (const void *)b2i_PrivateKey_bio; kv_int("ref.b2i_PrivateKey_bio", v != NULL);
    v = (const void *)b2i_PublicKey;      kv_int("ref.b2i_PublicKey", v != NULL);
    v = (const void *)b2i_PublicKey_bio;  kv_int("ref.b2i_PublicKey_bio", v != NULL);
    v = (const void *)d2i_PKCS8PrivateKey_bio;
    kv_int("ref.d2i_PKCS8PrivateKey_bio", v != NULL);
    v = (const void *)d2i_PKCS8PrivateKey_fp;
    kv_int("ref.d2i_PKCS8PrivateKey_fp", v != NULL);
    v = (const void *)i2b_PVK_bio;        kv_int("ref.i2b_PVK_bio", v != NULL);
    v = (const void *)i2b_PVK_bio_ex;     kv_int("ref.i2b_PVK_bio_ex", v != NULL);
    v = (const void *)i2b_PrivateKey_bio; kv_int("ref.i2b_PrivateKey_bio", v != NULL);
    v = (const void *)i2b_PublicKey_bio;  kv_int("ref.i2b_PublicKey_bio", v != NULL);
    v = (const void *)i2d_PKCS8PrivateKey_bio;
    kv_int("ref.i2d_PKCS8PrivateKey_bio", v != NULL);
    v = (const void *)i2d_PKCS8PrivateKey_fp;
    kv_int("ref.i2d_PKCS8PrivateKey_fp", v != NULL);
    v = (const void *)i2d_PKCS8PrivateKey_nid_bio;
    kv_int("ref.i2d_PKCS8PrivateKey_nid_bio", v != NULL);
    v = (const void *)i2d_PKCS8PrivateKey_nid_fp;
    kv_int("ref.i2d_PKCS8PrivateKey_nid_fp", v != NULL);
    v = (const void *)PEM_write_bio_PrivateKey_traditional;
    kv_int("ref.PEM_write_bio_PrivateKey_traditional", v != NULL);
    v = (const void *)d2i_AutoPrivateKey;  kv_int("ref.d2i_AutoPrivateKey", v != NULL);
    v = (const void *)d2i_AutoPrivateKey_ex;
    kv_int("ref.d2i_AutoPrivateKey_ex", v != NULL);
    v = (const void *)d2i_PrivateKey;      kv_int("ref.d2i_PrivateKey", v != NULL);
    v = (const void *)d2i_PrivateKey_ex;   kv_int("ref.d2i_PrivateKey_ex", v != NULL);
    v = (const void *)i2d_KeyParams;       kv_int("ref.i2d_KeyParams", v != NULL);
    v = (const void *)i2d_KeyParams_bio;   kv_int("ref.i2d_KeyParams_bio", v != NULL);
    v = (const void *)i2d_PKCS8PrivateKey; kv_int("ref.i2d_PKCS8PrivateKey", v != NULL);
    v = (const void *)i2d_PrivateKey;      kv_int("ref.i2d_PrivateKey", v != NULL);
    v = (const void *)i2d_PublicKey;       kv_int("ref.i2d_PublicKey", v != NULL);
    (void)v;
}

/* --------------------------------------------------------------------------------------------
 * i2d_evp.c -- the five writers.
 * ------------------------------------------------------------------------------------------ */

typedef int (*i2d_pkey_fn)(const EVP_PKEY *, unsigned char **);

static void emit_i2d(const char *key, i2d_pkey_fn fn, EVP_PKEY *pk)
{
    int n;
    unsigned char *buf, *q;

    if (pk == NULL) {
        kv_int(key, -1);
        return;
    }
    ERR_clear_error();
    n = fn(pk, NULL);
    kv_int(key, n);
    if (n > 0) {
        buf = OPENSSL_malloc((size_t)n);
        q = buf;
        if (buf != NULL && fn(pk, &q) > 0)
            kv_hex(key, buf, (size_t)n);
        OPENSSL_free(buf);
    }
    errs(key);
}

/* A mem BIO's contents as hex, then free it. */
static void drain_bio(const char *key, BIO *b)
{
    BUF_MEM *bm = NULL;

    BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, &bm);
    if (bm != NULL)
        kv_hex(key, (const unsigned char *)bm->data, bm->length);
    BIO_free(b);
}

static void arm_i2d(void)
{
    EVP_PKEY *rsa = legacy_rsa(), *dsa = legacy_dsa(), *ec = legacy_ec();

    describe("i2d.rsa.key", rsa);
    describe("i2d.dsa.key", dsa);
    describe("i2d.ec.key", ec);

    emit_i2d("i2d.KeyParams.rsa", i2d_KeyParams, rsa);
    emit_i2d("i2d.KeyParams.ec", i2d_KeyParams, ec);
    emit_i2d("i2d.PrivateKey.rsa", i2d_PrivateKey, rsa);
    emit_i2d("i2d.PrivateKey.dsa", i2d_PrivateKey, dsa);
    emit_i2d("i2d.PKCS8PrivateKey.rsa", i2d_PKCS8PrivateKey, rsa);
    emit_i2d("i2d.PKCS8PrivateKey.dsa", i2d_PKCS8PrivateKey, dsa);
    emit_i2d("i2d.PublicKey.rsa", i2d_PublicKey, rsa);
    emit_i2d("i2d.PublicKey.dsa", i2d_PublicKey, dsa);
    emit_i2d("i2d.PublicKey.ec", i2d_PublicKey, ec);

    /* The key-sized BIO writer: `i2d_KeyParams_bio` over a memory BIO. */
    if (ec != NULL) {
        ERR_clear_error();
        {
            BIO *b = BIO_new(BIO_s_mem());
            kv_int("i2d.KeyParams_bio.rc", i2d_KeyParams_bio(b, ec));
            drain_bio("i2d.KeyParams_bio.ec", b);
            errs("i2d.KeyParams_bio");
        }
    }

    EVP_PKEY_free(rsa);
    EVP_PKEY_free(dsa);
    EVP_PKEY_free(ec);
}

/* --------------------------------------------------------------------------------------------
 * pvkfmt.c -- the PVK and MSBLOB writers and readers.
 * ------------------------------------------------------------------------------------------ */

/* A reader that walks a cursor: `b2i_PrivateKey`/`b2i_PublicKey`. */
static void arm_b2i_memory(const char *key, EVP_PKEY *(*fn)(const unsigned char **, long),
                           const unsigned char *buf, size_t n)
{
    const unsigned char *p = buf;
    EVP_PKEY *pk;

    ERR_clear_error();
    pk = fn(&p, (long)n);
    describe(key, pk);
    errs(key);
    EVP_PKEY_free(pk);
}

static void arm_b2i_bio(const char *key, EVP_PKEY *(*fn)(BIO *),
                        const unsigned char *buf, size_t n)
{
    BIO *b = BIO_new_mem_buf(buf, (int)n);
    EVP_PKEY *pk;

    ERR_clear_error();
    pk = fn(b);
    describe(key, pk);
    errs(key);
    BIO_free(b);
    EVP_PKEY_free(pk);
}

static void arm_b2i_pvk(const char *key,
                        EVP_PKEY *(*fn)(BIO *, pem_password_cb *, void *),
                        const unsigned char *buf, size_t n)
{
    BIO *b = BIO_new_mem_buf(buf, (int)n);
    EVP_PKEY *pk;

    ERR_clear_error();
    pk = fn(b, NULL, NULL);
    describe(key, pk);
    errs(key);
    BIO_free(b);
    EVP_PKEY_free(pk);
}

static void arm_i2b_and_b2i(const char *label, EVP_PKEY *pk)
{
    char key[96];
    BIO *b;
    BUF_MEM *bm = NULL;
    unsigned char *privdata = NULL, *pubdata = NULL, *pvkdata = NULL;
    size_t privlen = 0, publen = 0, pvklen = 0;

    if (pk == NULL) {
        snprintf(key, sizeof(key), "i2b.%s.key", label);
        kv_int(key, 0);
        return;
    }

    /* i2b_PrivateKey_bio: the BUF_MEM is owned by the BIO, so the bytes are copied out before the
     * BIO is released. */
    b = BIO_new(BIO_s_mem());
    snprintf(key, sizeof(key), "i2b.PrivateKey_bio.%s", label);
    kv_int(key, i2b_PrivateKey_bio(b, pk));
    BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, &bm);
    if (bm != NULL) {
        privlen = bm->length;
        privdata = OPENSSL_malloc(privlen);
        memcpy(privdata, bm->data, privlen);
    }
    BIO_free(b);
    if (privdata != NULL) {
        snprintf(key, sizeof(key), "i2b.PrivateKey.%s", label);
        kv_hex(key, privdata, privlen);
    }

    bm = NULL;
    b = BIO_new(BIO_s_mem());
    snprintf(key, sizeof(key), "i2b.PublicKey_bio.%s", label);
    kv_int(key, i2b_PublicKey_bio(b, pk));
    BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, &bm);
    if (bm != NULL) {
        publen = bm->length;
        pubdata = OPENSSL_malloc(publen);
        memcpy(pubdata, bm->data, publen);
    }
    BIO_free(b);
    if (pubdata != NULL) {
        snprintf(key, sizeof(key), "i2b.PublicKey.%s", label);
        kv_hex(key, pubdata, publen);
    }

    /* i2b_PVK_bio at the unencrypted level 0; the encrypted level needs the legacy PVKKDF/RC4. */
    bm = NULL;
    b = BIO_new(BIO_s_mem());
    snprintf(key, sizeof(key), "i2b.PVK_bio.%s", label);
    kv_int(key, i2b_PVK_bio(b, pk, 0, NULL, NULL));
    BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, &bm);
    if (bm != NULL) {
        pvklen = bm->length;
        pvkdata = OPENSSL_malloc(pvklen);
        memcpy(pvkdata, bm->data, pvklen);
    }
    BIO_free(b);
    if (pvkdata != NULL) {
        snprintf(key, sizeof(key), "i2b.PVK.%s", label);
        kv_hex(key, pvkdata, pvklen);
    }

    b = BIO_new(BIO_s_mem());
    snprintf(key, sizeof(key), "i2b.PVK_bio_ex.%s", label);
    kv_int(key, i2b_PVK_bio_ex(b, pk, 0, NULL, NULL, NULL, NULL));
    BIO_free(b);

    /* The readers, over the bytes just written (a function of the fixed key alone). */
    if (privdata != NULL) {
        snprintf(key, sizeof(key), "b2i.PrivateKey.%s", label);
        arm_b2i_memory(key, b2i_PrivateKey, privdata, privlen);
        snprintf(key, sizeof(key), "b2i.PrivateKey_bio.%s", label);
        arm_b2i_bio(key, b2i_PrivateKey_bio, privdata, privlen);
    }
    if (pubdata != NULL) {
        snprintf(key, sizeof(key), "b2i.PublicKey.%s", label);
        arm_b2i_memory(key, b2i_PublicKey, pubdata, publen);
        snprintf(key, sizeof(key), "b2i.PublicKey_bio.%s", label);
        arm_b2i_bio(key, b2i_PublicKey_bio, pubdata, publen);
    }
    if (pvkdata != NULL) {
        snprintf(key, sizeof(key), "b2i.PVK_bio.%s", label);
        arm_b2i_pvk(key, b2i_PVK_bio, pvkdata, pvklen);
        snprintf(key, sizeof(key), "b2i.PVK_bio_ex.%s", label);
        ERR_clear_error();
        {
            BIO *bp = BIO_new_mem_buf(pvkdata, (int)pvklen);
            EVP_PKEY *got = b2i_PVK_bio_ex(bp, NULL, NULL, NULL, NULL);
            describe(key, got);
            errs(key);
            BIO_free(bp);
            EVP_PKEY_free(got);
        }
    }

    OPENSSL_free(privdata);
    OPENSSL_free(pubdata);
    OPENSSL_free(pvkdata);
}

static void arm_pvkfmt_refusals(void)
{
    /* A 16-byte body whose bType is 0: `ossl_do_blob_header` refuses 0, and `do_b2i_key` raises
     * PEM_R_KEYBLOB_HEADER_PARSE_ERROR at its own coordinate. */
    static const unsigned char btype0[16] = { 0 };
    /* Too short for even the header: `ossl_b2i_bio`'s BIO_read shortfall. */
    static const unsigned char tiny[8] = { 0 };

    arm_b2i_memory("refuse.b2i_PrivateKey.btype0", b2i_PrivateKey, btype0, sizeof(btype0));
    arm_b2i_memory("refuse.b2i_PublicKey.btype0", b2i_PublicKey, btype0, sizeof(btype0));
    arm_b2i_memory("refuse.b2i_PrivateKey.tiny", b2i_PrivateKey, tiny, sizeof(tiny));
    arm_b2i_bio("refuse.b2i_PrivateKey_bio.tiny", b2i_PrivateKey_bio, tiny, sizeof(tiny));
    ERR_clear_error();
    {
        BIO *b = BIO_new_mem_buf(tiny, (int)sizeof(tiny));
        EVP_PKEY *pk;
        kv_int("refuse.b2i_PVK_bio.tiny.rc", (pk = b2i_PVK_bio(b, NULL, NULL)) != NULL);
        errs("refuse.b2i_PVK_bio.tiny");
        EVP_PKEY_free(pk);
        BIO_free(b);
    }
}

static void arm_pvkfmt(void)
{
    EVP_PKEY *rsa = legacy_rsa(), *dsa = legacy_dsa();

    arm_i2b_and_b2i("rsa", rsa);
    arm_i2b_and_b2i("dsa", dsa);
    arm_pvkfmt_refusals();

    EVP_PKEY_free(rsa);
    EVP_PKEY_free(dsa);
}

/* --------------------------------------------------------------------------------------------
 * pem_pkey.c -- `PEM_write_bio_PrivateKey_traditional`.
 * ------------------------------------------------------------------------------------------ */

static void arm_traditional(void)
{
    EVP_PKEY *rsa = legacy_rsa(), *dsa = legacy_dsa(), *ec = legacy_ec();

    /* The EC traditional spelling is held pending: the underlying phase-8 `old_ec_priv_encode`
     * emits `0x20`/`0x21` for the `[0]`/`[1]` explicit tags where the authority emits
     * `0xa0`/`0xa1`, so a byte comparison would measure that defect and not this unit. */
    ERR_clear_error();
    {
        BIO *b = BIO_new(BIO_s_mem());
        kv_int("pem.traditional.rsa.rc",
               PEM_write_bio_PrivateKey_traditional(b, rsa, NULL, NULL, 0, NULL, NULL));
        drain_bio("pem.traditional.rsa", b);
        errs("pem.traditional.rsa");
    }
    ERR_clear_error();
    {
        BIO *b = BIO_new(BIO_s_mem());
        kv_int("pem.traditional.dsa.rc",
               PEM_write_bio_PrivateKey_traditional(b, dsa, NULL, NULL, 0, NULL, NULL));
        drain_bio("pem.traditional.dsa", b);
        errs("pem.traditional.dsa");
    }

    EVP_PKEY_free(rsa);
    EVP_PKEY_free(dsa);
    EVP_PKEY_free(ec);
}

/* --------------------------------------------------------------------------------------------
 * pem_pk8.c -- the DER PKCS#8 readers and writers.
 * ------------------------------------------------------------------------------------------ */

static void arm_pk8(void)
{
    EVP_PKEY *rsa = legacy_rsa();

    if (rsa == NULL) {
        return;
    }
    /* i2d_PKCS8PrivateKey_bio / _fp over a legacy key and no cipher: the unencrypted arm. */
    ERR_clear_error();
    {
        BIO *b = BIO_new(BIO_s_mem());
        kv_int("pk8.i2d_bio.rc",
               i2d_PKCS8PrivateKey_bio(b, rsa, NULL, NULL, 0, NULL, NULL));
        drain_bio("pk8.i2d_bio.rsa", b);
        errs("pk8.i2d_bio");
    }
    ERR_clear_error();
    {
        FILE *fp = tmpfile();
        if (fp != NULL)
            kv_int("pk8.i2d_fp.rc", i2d_PKCS8PrivateKey_fp(fp, rsa, NULL, NULL, 0, NULL, NULL));
        if (fp != NULL)
            fclose(fp);
        errs("pk8.i2d_fp");
    }

    /* d2i_PKCS8PrivateKey_bio / _fp over the fixed PBES2 vector, passphrase through the `u`
     * argument (`PEM_def_callback` reads it). */
    ERR_clear_error();
    {
        BIO *b = BIO_new_mem_buf(rsa_enc_der, (int)sizeof(rsa_enc_der));
        EVP_PKEY *pk = d2i_PKCS8PrivateKey_bio(b, NULL, NULL, (void *)"12345");
        describe("pk8.d2i_bio.rsa", pk);
        errs("pk8.d2i_bio");
        EVP_PKEY_free(pk);
        BIO_free(b);
    }
    ERR_clear_error();
    {
        FILE *fp = tmpfile();
        if (fp != NULL) {
            EVP_PKEY *pk;
            fwrite(rsa_enc_der, 1, sizeof(rsa_enc_der), fp);
            rewind(fp);
            pk = d2i_PKCS8PrivateKey_fp(fp, NULL, NULL, (void *)"12345");
            describe("pk8.d2i_fp.rsa", pk);
            errs("pk8.d2i_fp");
            EVP_PKEY_free(pk);
            fclose(fp);
        }
    }

    /* The wrong-passphrase refusal: the decrypt fails and the coordinate is the authority's. */
    ERR_clear_error();
    {
        BIO *b = BIO_new_mem_buf(rsa_enc_der, (int)sizeof(rsa_enc_der));
        EVP_PKEY *pk = d2i_PKCS8PrivateKey_bio(b, NULL, NULL, (void *)"wrong");
        describe("pk8.d2i_bio.wrong_pass", pk);
        errs("pk8.d2i_bio.wrong_pass");
        EVP_PKEY_free(pk);
        BIO_free(b);
    }

    EVP_PKEY_free(rsa);
}

/* --------------------------------------------------------------------------------------------
 * d2i_pr.c -- the private-key readers, both arms.
 * ------------------------------------------------------------------------------------------ */

static void arm_d2i_input(const char *key, int type, const unsigned char *buf, size_t n)
{
    const unsigned char *p = buf;
    EVP_PKEY *pk;

    ERR_clear_error();
    pk = d2i_PrivateKey(type, NULL, &p, (long)n);
    describe(key, pk);
    errs(key);
    EVP_PKEY_free(pk);
}

static void arm_auto_input(const char *key, const unsigned char *buf, size_t n)
{
    const unsigned char *p = buf;
    EVP_PKEY *pk;

    ERR_clear_error();
    pk = d2i_AutoPrivateKey(NULL, &p, (long)n);
    describe(key, pk);
    errs(key);
    EVP_PKEY_free(pk);
}

static void arm_d2i_input_ex(const char *key, int type, const unsigned char *buf, size_t n)
{
    const unsigned char *p = buf;
    EVP_PKEY *pk;

    ERR_clear_error();
    pk = d2i_PrivateKey_ex(type, NULL, &p, (long)n, NULL, NULL);
    describe(key, pk);
    errs(key);
    EVP_PKEY_free(pk);
}

static void arm_auto_input_ex(const char *key, const unsigned char *buf, size_t n)
{
    const unsigned char *p = buf;
    EVP_PKEY *pk;

    ERR_clear_error();
    pk = d2i_AutoPrivateKey_ex(NULL, &p, (long)n, NULL, NULL);
    describe(key, pk);
    errs(key);
    EVP_PKEY_free(pk);
}

static void arm_d2i(void)
{
    const unsigned char *p;
    unsigned char *pkcs1 = NULL, *pkcs8 = NULL;
    int n1 = 0, n8 = 0;
    EVP_PKEY *rsa = legacy_rsa();
    static const unsigned char garbage[8] = { 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0 };

    /* The provider arm: a PKCS#8 `PrivateKeyInfo` named by keytype, and auto-derived. */
    arm_d2i_input("d2i.PrivateKey.rsa_pkcs8", EVP_PKEY_RSA, rsa_pkcs8_der, sizeof(rsa_pkcs8_der));
    arm_d2i_input_ex("d2i.PrivateKey_ex.rsa_pkcs8", EVP_PKEY_RSA, rsa_pkcs8_der,
                     sizeof(rsa_pkcs8_der));
    arm_auto_input("d2i.AutoPrivateKey.rsa_pkcs8", rsa_pkcs8_der, sizeof(rsa_pkcs8_der));
    arm_auto_input_ex("d2i.AutoPrivateKey_ex.rsa_pkcs8", rsa_pkcs8_der,
                      sizeof(rsa_pkcs8_der));
    arm_d2i_input("d2i.PrivateKey.dsa_pkcs8", EVP_PKEY_DSA, dsa_pkcs8_der, sizeof(dsa_pkcs8_der));

    /* The traditional bodies: the structure the decoder is asked for as `type-specific`, and the
     * element-count discrimination `d2i_AutoPrivateKey_legacy` runs. */
    arm_d2i_input("d2i.PrivateKey.rsa_pkcs1", EVP_PKEY_RSA, rsa_pkcs1_der,
                  sizeof(rsa_pkcs1_der));
    arm_auto_input("d2i.AutoPrivateKey.rsa_pkcs1", rsa_pkcs1_der, sizeof(rsa_pkcs1_der));
    arm_auto_input("d2i.AutoPrivateKey.dsa_trad", dsa_trad_der, sizeof(dsa_trad_der));

    /* A writer-then-reader pair over the same side's own encoding: the bytes are printed by the
     * writer above, so a disagreement is visible there as well as here. */
    if (rsa != NULL) {
        p = NULL;
        n1 = i2d_PrivateKey(rsa, NULL);
        if (n1 > 0) {
            pkcs1 = OPENSSL_malloc((size_t)n1);
            p = pkcs1;
            i2d_PrivateKey(rsa, (unsigned char **)&p);
            arm_d2i_input("d2i.PrivateKey.self_traditional", EVP_PKEY_RSA, pkcs1, (size_t)n1);
        }
        p = NULL;
        n8 = i2d_PKCS8PrivateKey(rsa, NULL);
        if (n8 > 0) {
            pkcs8 = OPENSSL_malloc((size_t)n8);
            p = pkcs8;
            i2d_PKCS8PrivateKey(rsa, (unsigned char **)&p);
            arm_auto_input("d2i.AutoPrivateKey.self_pkcs8", pkcs8, (size_t)n8);
        }
    }

    /* The refusals: a body that is neither PKCS#8 nor a type-specific key. */
    arm_d2i_input("refuse.d2i.PrivateKey.garbage", EVP_PKEY_RSA, garbage, sizeof(garbage));
    arm_auto_input("refuse.d2i.AutoPrivateKey.garbage", garbage, sizeof(garbage));

    OPENSSL_free(pkcs1);
    OPENSSL_free(pkcs8);
    EVP_PKEY_free(rsa);
}

int main(void)
{
    arm_reference();
    ERR_clear_error();
    arm_i2d();
    ERR_clear_error();
    arm_pvkfmt();
    ERR_clear_error();
    arm_traditional();
    ERR_clear_error();
    arm_pk8();
    ERR_clear_error();
    arm_d2i();
    ERR_clear_error();
    return 0;
}
