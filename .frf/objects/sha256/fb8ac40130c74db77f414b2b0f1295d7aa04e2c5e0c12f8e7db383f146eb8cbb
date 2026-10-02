/*
 * RT-X509-ACERT -- the Phase 11.3 attribute-certificate surface, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell, whose two transcripts are diffed line by line (`phase11_courts.py`). Every
 * observation is a small integer, a byte-for-byte equality, a `nonnull`/`null`, or an error
 * coordinate (`lib.reason`) -- never an address and never an allocator-dependent value, so the
 * transcript is a function of the library and not of the probe's own frame
 * (`probe_hygiene.py` recompiles it at -O0/-O1/-O2 and requires that).
 *
 * What it drives, and how
 * -----------------------
 * The fixture is a fixed `X509_ACERT` DER built here from literal bytes (`RT_X509_ACERT_DER`):
 * version 1 (v2), an all-optional-empty `X509_HOLDER`, a `v2Form` issuer with an empty
 * `issuerName`, a `sha256WithRSAEncryption` `signature`, serial `0x1234`, a 2024/2025
 * `Validity`, an empty `attributes` sequence and an empty signature bit string. It exercises the
 * whole `x509_acert.c`/`x509aset.c`/`x_ietfatt.c`/`x_all.c` surface:
 *
 *   * the seven item templates, their `_new`/`_free`/`_it`/`d2i_`/`i2d_`/`_dup_` groups and the
 *     `d2i`/`i2d` byte-for-byte round trip (the decoded object re-encodes to the fixture exactly);
 *   * every `get0`/`get_` accessor, over the fixture and over fresh objects;
 *   * the twelve setters, driving each and reading the effect back through the matching getter;
 *   * the eight attribute containers (add/duplicate/get/delete/by-NID/by-OBJ/by-txt) and
 *     `X509_ACERT_add_attr_nconf` over a real `NCONF`;
 *   * the four `X509_ACERT` PEM spellings, `_fp` and `_bio`, written and read back;
 *   * the `x_ietfatt.c` items and accessors, its `print`, and its mixed-choice `d2i` refusal;
 *   * the `x_all.c` doors: `X509_ACERT_{sign,sign_ctx,verify}`, `X509_REQ_{digest,verify,
 *     verify_ex,sign,sign_ctx}` and the eight `_fp`/`_bio` stream faces (the `X509_REQ` fixture
 *     is `rt_x509_der.h`'s `RT_X509_REQ_DER`).
 *
 * The sign/verify arms drive the NULL-key refusals with a fresh `EVP_MD_CTX` where a context is
 * needed; no key material is generated or read (nothing here draws randomness), and
 * `X509_load_http`/`X509_CRL_load_http` are not driven because their `http` unit is unlanded.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509_acert.h>
#include <openssl/x509v3.h>

#include "rt_x509_der.h"

/* ---------------------------------------------------------------------------------------------
 * A fixed attribute certificate, built from literal DER.
 *
 *   SEQUENCE {                        30 54
 *     acinfo SEQUENCE                 30 40
 *       version INTEGER 1             02 01 01
 *       holder SEQUENCE {}            30 00
 *       issuer [0] v2Form {}          a0 00
 *       signature AlgorithmIdentifier 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00
 *       serialNumber INTEGER 0x1234   02 02 12 34
 *       validity SEQUENCE             30 22
 *         notBefore GeneralizedTime   18 0f 32 30 32 34 30 31 30 31 30 30 30 30 30 30 5a
 *         notAfter  GeneralizedTime   18 0f 32 30 32 35 30 31 30 31 30 30 30 30 30 30 5a
 *       attributes SEQUENCE {}        30 00
 *     sig_alg AlgorithmIdentifier     30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00
 *     signature BIT STRING            03 01 00
 *   }
 * The two GeneralizedTimes are "20240101000000Z" and "20250101000000Z"; the algorithm OID is
 * 1.2.840.113549.1.1.11 (sha256WithRSAEncryption) with a NULL parameter.
 * --------------------------------------------------------------------------------------------- */

static const unsigned char RT_X509_ACERT_DER[] = {
    0x30, 0x54,
    0x30, 0x40,
    0x02, 0x01, 0x01,
    0x30, 0x00,
    0xa0, 0x00,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x02, 0x02, 0x12, 0x34,
    0x30, 0x22,
    0x18, 0x0f, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a,
    0x18, 0x0f, 0x32, 0x30, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a,
    0x30, 0x00,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x01, 0x00,
};

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`. No address is ever printed.
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_ptr(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

/* The first error on the queue as `lib.reason`, then the queue is cleared. */
static void out_err(const char *key)
{
    unsigned long e = ERR_get_error();

    if (e == 0) {
        printf("%s=none\n", key);
        return;
    }
    printf("%s=%d.%d\n", key, ERR_GET_LIB(e), ERR_GET_REASON(e));
    ERR_clear_error();
}

static void out_hex(const char *key, const unsigned char *buf, long len)
{
    long i;

    printf("%s.len=%ld\n", key, len);
    printf("%s.hex=", key);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* The bytes a memory BIO holds; the BIO is rewound for the next arm. */
static void emit_mem(const char *key, BIO *b)
{
    char *data = NULL;
    long n = BIO_get_mem_data(b, &data);

    out_hex(key, (const unsigned char *)data, n);
    BIO_reset(b);
}

/* A 64-bit FNV-1a digest of a byte span: a stable function of the printed text alone. */
static unsigned long long fnv1a(const unsigned char *b, size_t n)
{
    unsigned long long h = 1469598103934665603ULL;
    size_t i;

    for (i = 0; i < n; i++) {
        h ^= (unsigned long long)b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* The exact bytes a printer produced, as length and digest. */
static void out_text(const char *key, const unsigned char *buf, long len)
{
    if (len < 0)
        len = 0;
    printf("%s.len=%ld\n", key, len);
    printf("%s.fnv=%016llx\n", key, fnv1a(buf, (size_t)len));
}

/* Print the contents of a memory BIO as length and digest, then rewind it. */
static void out_mem(const char *key, BIO *b)
{
    char *data = NULL;
    long len = BIO_get_mem_data(b, &data);

    out_text(key, (const unsigned char *)data, len);
    BIO_reset(b);
}

static CONF *mk_acert_conf(void)
{
    static const char text[] = "[attrs]\n"
                               "friendlyName=hello\n";
    BIO *b = BIO_new_mem_buf(text, -1);
    CONF *c = NCONF_new(NULL);

    NCONF_load_bio(c, b, NULL);
    BIO_free(b);
    return c;
}

/*
 * A signing context that carries a key-management context but no key. The `_ctx` sign doors
 * resolve the key out of the context with `EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx))`,
 * and the authority dereferences a NULL `EVP_PKEY_CTX` there rather than returning NULL -- so a
 * bare `EVP_MD_CTX_new()` is a genuine fault boundary. Attaching a fresh `EVP_PKEY_CTX` (which has
 * a NULL key) reaches the doors' own NULL-key refusal instead, identically on both sides.
 */
static EVP_MD_CTX *mk_sig_ctx(void)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
    return ctx;
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.3 -- `crypto/x509/x509_acert.c`: the item groups and lifecycle.
 *
 * `X509_ACERT_it`/`X509_ACERT_INFO_it` are non-NULL statics; the three `_new`/`_free` pairs of the
 * subordinate items (`X509_ACERT_INFO`, `OSSL_ISSUER_SERIAL`, `OSSL_OBJECT_DIGEST_INFO`,
 * `X509_ACERT_ISSUER_V2FORM`) round-trip and accept NULL. The DER fixture decodes and re-encodes
 * byte for byte.
 * --------------------------------------------------------------------------------------------- */

static void drive_acert_items(void)
{
    const unsigned char *p = RT_X509_ACERT_DER;
    X509_ACERT *a = d2i_X509_ACERT(NULL, &p, (long)sizeof RT_X509_ACERT_DER);
    X509_ACERT_INFO *info;
    OSSL_ISSUER_SERIAL *is;
    OSSL_OBJECT_DIGEST_INFO *odi;
    X509_ACERT_ISSUER_V2FORM *v2;
    X509_NAME *nm;
    ASN1_INTEGER *ser;
    ASN1_BIT_STRING *uid;
    X509_ALGOR *algor;
    ASN1_BIT_STRING *dig;

    ERR_clear_error();

    out_ptr("acert_it", (const void *)X509_ACERT_it());
    out_ptr("acert_info_it", (const void *)X509_ACERT_INFO_it());

    info = X509_ACERT_INFO_new();
    out_ptr("acert_info.new", info);
    X509_ACERT_INFO_free(info);
    X509_ACERT_INFO_free(NULL);
    out_int("acert_info.free", 1);

    v2 = X509_ACERT_ISSUER_V2FORM_new();
    out_ptr("v2form.new", v2);
    X509_ACERT_ISSUER_V2FORM_free(v2);
    X509_ACERT_ISSUER_V2FORM_free(NULL);
    out_int("v2form.free", 1);

    is = OSSL_ISSUER_SERIAL_new();
    out_ptr("isss.new", is);
    out_ptr("isss.get0_serial", (const void *)OSSL_ISSUER_SERIAL_get0_serial(is));
    out_ptr("isss.get0_issuer", (const void *)OSSL_ISSUER_SERIAL_get0_issuer(is));
    out_ptr("isss.get0_issuerUID", (const void *)OSSL_ISSUER_SERIAL_get0_issuerUID(is));

    nm = X509_NAME_new();
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               (const unsigned char *)"probe", -1, -1, 0);
    out_int("isss.set1_issuer", OSSL_ISSUER_SERIAL_set1_issuer(is, nm));
    out_ptr("isss.get0_issuer.after", (const void *)OSSL_ISSUER_SERIAL_get0_issuer(is));

    ser = ASN1_INTEGER_new();
    ASN1_INTEGER_set(ser, 7);
    out_int("isss.set1_serial", OSSL_ISSUER_SERIAL_set1_serial(is, ser));
    out_int("isss.get0_serial.value", ASN1_INTEGER_get(OSSL_ISSUER_SERIAL_get0_serial(is)));

    uid = ASN1_BIT_STRING_new();
    out_int("isss.set1_issuerUID", OSSL_ISSUER_SERIAL_set1_issuerUID(is, uid));
    out_ptr("isss.get0_issuerUID.after", (const void *)OSSL_ISSUER_SERIAL_get0_issuerUID(is));
    out_int("isss.set1_issuerUID.replace", OSSL_ISSUER_SERIAL_set1_issuerUID(is, uid));

    OSSL_ISSUER_SERIAL_free(is);
    OSSL_ISSUER_SERIAL_free(NULL);
    out_int("isss.free", 1);

    odi = OSSL_OBJECT_DIGEST_INFO_new();
    out_ptr("odi.new", odi);
    {
        int dot = -1;
        const X509_ALGOR *da = NULL;
        const ASN1_BIT_STRING *db = NULL;

        OSSL_OBJECT_DIGEST_INFO_get0_digest(odi, &dot, &da, &db);
        out_int("odi.get0_digest.type", dot);
        out_ptr("odi.get0_digest.alg", (const void *)da);
        out_ptr("odi.get0_digest.digest", (const void *)db);
    }
    algor = X509_ALGOR_new();
    dig = ASN1_BIT_STRING_new();
    out_int("odi.set1_digest", OSSL_OBJECT_DIGEST_INFO_set1_digest(odi, 1, algor, dig));
    {
        int dot = -1;
        const X509_ALGOR *da = NULL;
        const ASN1_BIT_STRING *db = NULL;

        OSSL_OBJECT_DIGEST_INFO_get0_digest(odi, &dot, &da, &db);
        out_int("odi.get0_digest.type.after", dot);
        out_ptr("odi.get0_digest.digest.after", (const void *)db);
    }
    OSSL_OBJECT_DIGEST_INFO_get0_digest(odi, NULL, NULL, NULL);
    out_int("odi.get0_digest.nulls", 1);
    OSSL_OBJECT_DIGEST_INFO_free(odi);
    OSSL_OBJECT_DIGEST_INFO_free(NULL);
    out_int("odi.free", 1);
    X509_ALGOR_free(algor);
    ASN1_BIT_STRING_free(dig);
    ASN1_BIT_STRING_free(uid);
    ASN1_INTEGER_free(ser);
    X509_NAME_free(nm);

    /* The decoded fixture and its accessors. */
    out_ptr("acert.d2i", a);
    if (a == NULL)
        return;

    out_int("acert.get_version", X509_ACERT_get_version(a));
    out_ptr("acert.get0_serialNumber", (const void *)X509_ACERT_get0_serialNumber(a));
    out_int("acert.get0_serialNumber.value",
            ASN1_INTEGER_get(X509_ACERT_get0_serialNumber(a)));
    out_int("acert.get_signature_nid", X509_ACERT_get_signature_nid(a));
    out_ptr("acert.get0_info_sigalg", (const void *)X509_ACERT_get0_info_sigalg(a));
    out_ptr("acert.get0_issuerName", (const void *)X509_ACERT_get0_issuerName(a));
    out_ptr("acert.get0_issuerUID", (const void *)X509_ACERT_get0_issuerUID(a));
    out_ptr("acert.get0_holder_entityName", (const void *)X509_ACERT_get0_holder_entityName(a));
    out_ptr("acert.get0_holder_baseCertId", (const void *)X509_ACERT_get0_holder_baseCertId(a));
    out_ptr("acert.get0_holder_digest", (const void *)X509_ACERT_get0_holder_digest(a));
    out_ptr("acert.get0_notBefore", (const void *)X509_ACERT_get0_notBefore(a));
    out_ptr("acert.get0_notAfter", (const void *)X509_ACERT_get0_notAfter(a));
    out_ptr("acert.get0_extensions", (const void *)X509_ACERT_get0_extensions(a));
    {
        const ASN1_BIT_STRING *sig = NULL;
        const X509_ALGOR *alg = NULL;

        X509_ACERT_get0_signature(a, &sig, &alg);
        out_ptr("acert.get0_signature.sig", (const void *)sig);
        out_ptr("acert.get0_signature.alg", (const void *)alg);
    }
    out_int("acert.get_attr_count", X509_ACERT_get_attr_count(a));

    /* The extension readers: none present, so both arm answers agree. */
    ERR_clear_error();
    {
        int crit = -9;
        int idx = -9;
        void *v = X509_ACERT_get_ext_d2i(a, NID_basic_constraints, &crit, &idx);

        out_ptr("acert.get_ext_d2i", v);
        out_int("acert.get_ext_d2i.crit", crit);
        out_int("acert.get_ext_d2i.idx", idx);
    }
    ERR_clear_error();
    out_int("acert.add1_ext_i2d.delete",
            X509_ACERT_add1_ext_i2d(a, NID_basic_constraints, NULL, 0, X509V3_ADD_DELETE));
    out_err("acert.add1_ext_i2d.delete.err");

    /* The DER round trip: the decoded object re-encodes to the fixture exactly. */
    {
        unsigned char *der = NULL;
        int len = i2d_X509_ACERT(a, &der);

        out_int("acert.i2d.len", len);
        out_hex("acert.i2d", der, len);
        out_int("acert.i2d.equals_fixture",
                len == (int)sizeof RT_X509_ACERT_DER
                    && der != NULL
                    && memcmp(der, RT_X509_ACERT_DER, (size_t)len) == 0);
        OPENSSL_free(der);
    }

    {
        X509_ACERT *b = X509_ACERT_dup(a);

        out_ptr("acert.dup", b);
        {
            char *m2 = NULL;
            long n2 = 0;

            if (b != NULL) {
                unsigned char *der = NULL;
                int len = i2d_X509_ACERT(b, &der);

                n2 = len;
                m2 = (char *)der;
            }
            out_int("acert.dup.i2d.len", n2);
            out_int("acert.dup.equals_fixture",
                    n2 == (long)sizeof RT_X509_ACERT_DER
                        && m2 != NULL
                        && memcmp(m2, RT_X509_ACERT_DER, (size_t)n2) == 0);
            OPENSSL_free(m2);
        }
        X509_ACERT_free(b);
    }
    X509_ACERT_free(a);
    X509_ACERT_free(NULL);
    out_int("acert.free", 1);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.3 -- `crypto/x509/x509aset.c`: the twelve setters.
 *
 * A fresh object is driven through each setter and the effect read back through the matching
 * `x509_acert.c` getter; one wrong-type `set1_notBefore` shows `replace_gentime`'s type refusal.
 * --------------------------------------------------------------------------------------------- */

static void drive_acert_setters(void)
{
    X509_ACERT *a = X509_ACERT_new();
    X509_NAME *nm = X509_NAME_new();
    X509_NAME *nm2 = X509_NAME_new();
    ASN1_INTEGER *ser = ASN1_INTEGER_new();
    ASN1_INTEGER *bad = ASN1_INTEGER_new();
    ASN1_GENERALIZEDTIME *tb = ASN1_GENERALIZEDTIME_new();
    ASN1_GENERALIZEDTIME *ta = ASN1_GENERALIZEDTIME_new();
    X509_ALGOR *algor = X509_ALGOR_new();
    ASN1_BIT_STRING *dig = ASN1_BIT_STRING_new();
    OSSL_ISSUER_SERIAL *is = OSSL_ISSUER_SERIAL_new();
    OSSL_OBJECT_DIGEST_INFO *odi = OSSL_OBJECT_DIGEST_INFO_new();
    GENERAL_NAMES *gn = sk_GENERAL_NAME_new_null();
    GENERAL_NAME *g = GENERAL_NAME_new();

    ERR_clear_error();

    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               (const unsigned char *)"probe", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm2, "CN", MBSTRING_ASC,
                               (const unsigned char *)"holder", -1, -1, 0);
    ASN1_INTEGER_set(ser, 0x1000);
    ASN1_INTEGER_set(bad, 1);
    ASN1_GENERALIZEDTIME_set_string(tb, "20240101000000Z");
    ASN1_GENERALIZEDTIME_set_string(ta, "20250101000000Z");

    out_int("set.version", X509_ACERT_set_version(a, X509_ACERT_VERSION_2));
    out_int("set.get_version", X509_ACERT_get_version(a));
    out_int("set.serialNumber", X509_ACERT_set1_serialNumber(a, ser));
    out_int("set.get0_serialNumber.value",
            ASN1_INTEGER_get(X509_ACERT_get0_serialNumber(a)));
    out_int("set.notBefore", X509_ACERT_set1_notBefore(a, tb));
    out_ptr("set.get0_notBefore", (const void *)X509_ACERT_get0_notBefore(a));
    out_int("set.notAfter", X509_ACERT_set1_notAfter(a, ta));
    out_ptr("set.get0_notAfter", (const void *)X509_ACERT_get0_notAfter(a));

    /* `replace_gentime` refuses a source whose type is not GENERALIZEDTIME. */
    out_int("set.notBefore.badtype",
            X509_ACERT_set1_notBefore(a, (const ASN1_GENERALIZEDTIME *)bad));

    out_int("set.issuerName", X509_ACERT_set1_issuerName(a, nm));
    out_ptr("set.get0_issuerName", (const void *)X509_ACERT_get0_issuerName(a));

    OSSL_ISSUER_SERIAL_set1_issuer(is, nm);
    OSSL_ISSUER_SERIAL_set1_serial(is, ser);
    X509_ACERT_set0_holder_baseCertId(a, is);
    out_ptr("set.get0_holder_baseCertId", (const void *)X509_ACERT_get0_holder_baseCertId(a));

    OSSL_OBJECT_DIGEST_INFO_set1_digest(odi, 0, algor, dig);
    X509_ACERT_set0_holder_digest(a, odi);
    out_ptr("set.get0_holder_digest", (const void *)X509_ACERT_get0_holder_digest(a));

    GENERAL_NAME_set0_value(g, GEN_DIRNAME, nm2);
    sk_GENERAL_NAME_push(gn, g);
    X509_ACERT_set0_holder_entityName(a, gn);
    out_ptr("set.get0_holder_entityName", (const void *)X509_ACERT_get0_holder_entityName(a));
    out_int("set.get0_holder_entityName.count",
            sk_GENERAL_NAME_num(X509_ACERT_get0_holder_entityName(a)));

    X509_ACERT_free(a);
    X509_NAME_free(nm);
    ASN1_INTEGER_free(ser);
    ASN1_INTEGER_free(bad);
    ASN1_GENERALIZEDTIME_free(tb);
    ASN1_GENERALIZEDTIME_free(ta);
    X509_ALGOR_free(algor);
    ASN1_BIT_STRING_free(dig);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.3 -- the attribute containers (`x509_acert.c:190-312`).
 *
 * Four attributes are added through the four add doors, read back by count/NID/OBJ/index, one is
 * deleted, and the two out-of-range refusals are observed. `X509_ACERT_add_attr_nconf` runs over a
 * real `NCONF` section and its missing-section refusal.
 * --------------------------------------------------------------------------------------------- */

static void drive_acert_attrs(void)
{
    X509_ACERT *a = X509_ACERT_new();
    X509_ATTRIBUTE *at;

    ERR_clear_error();

    out_ptr("attr.new", a);
    out_int("attr.add_by_NID",
            X509_ACERT_add1_attr_by_NID(a, NID_friendlyName, V_ASN1_OCTET_STRING,
                                        (const void *)"abc", 3));
    out_int("attr.count.1", X509_ACERT_get_attr_count(a));
    out_int("attr.get_by_NID", X509_ACERT_get_attr_by_NID(a, NID_friendlyName, -1));
    out_int("attr.get_by_NID.miss", X509_ACERT_get_attr_by_NID(a, NID_subject_alt_name, -1));
    out_int("attr.add_by_OBJ",
            X509_ACERT_add1_attr_by_OBJ(a, OBJ_nid2obj(NID_friendlyName), V_ASN1_OCTET_STRING,
                                        (const void *)"de", 2));
    out_int("attr.get_by_OBJ", X509_ACERT_get_attr_by_OBJ(a, OBJ_nid2obj(NID_friendlyName), -1));
    out_int("attr.add_by_txt",
            X509_ACERT_add1_attr_by_txt(a, "friendlyName", V_ASN1_OCTET_STRING,
                                        (const unsigned char *)"fg", 2));
    out_int("attr.count.3", X509_ACERT_get_attr_count(a));

    at = X509_ATTRIBUTE_create_by_NID(NULL, NID_friendlyName, V_ASN1_OCTET_STRING,
                                      (const void *)"hi", 2);
    out_ptr("attr.create", at);
    out_int("attr.add1_attr", X509_ACERT_add1_attr(a, at));
    X509_ATTRIBUTE_free(at);
    out_int("attr.count.4", X509_ACERT_get_attr_count(a));

    out_ptr("attr.get_attr.0", (const void *)X509_ACERT_get_attr(a, 0));
    ERR_clear_error();
    out_ptr("attr.get_attr.oob", (const void *)X509_ACERT_get_attr(a, 99));
    out_err("attr.get_attr.oob.err");

    {
        X509_ATTRIBUTE *d = X509_ACERT_delete_attr(a, 0);

        out_ptr("attr.delete.0", (const void *)d);
        X509_ATTRIBUTE_free(d);
    }
    out_int("attr.count.3b", X509_ACERT_get_attr_count(a));
    ERR_clear_error();
    out_ptr("attr.delete.oob", (const void *)X509_ACERT_delete_attr(a, 99));
    out_err("attr.delete.oob.err");

    {
        CONF *c = mk_acert_conf();

        ERR_clear_error();
        out_int("attr.nconf", X509_ACERT_add_attr_nconf(c, "attrs", a));
        out_err("attr.nconf.err");
        out_int("attr.nconf.count", X509_ACERT_get_attr_count(a));
        ERR_clear_error();
        out_int("attr.nconf.missing", X509_ACERT_add_attr_nconf(c, "nosuch", a));
        out_err("attr.nconf.missing.err");
        NCONF_free(c);
    }

    X509_ACERT_free(a);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.3 -- the four PEM spellings (`IMPLEMENT_PEM_rw(X509_ACERT, ...)`, `x509_acert.c:77`).
 *
 * The BIO writer's exact bytes are printed; the BIO reader reads them back. The `FILE *` pair
 * runs through a `tmpfile`.
 * --------------------------------------------------------------------------------------------- */

static void drive_acert_pem(void)
{
    const unsigned char *p = RT_X509_ACERT_DER;
    X509_ACERT *a = d2i_X509_ACERT(NULL, &p, (long)sizeof RT_X509_ACERT_DER);
    BIO *b = BIO_new(BIO_s_mem());

    ERR_clear_error();
    out_ptr("pem.acert", a);
    if (a == NULL) {
        BIO_free(b);
        return;
    }

    out_int("pem.write_bio", PEM_write_bio_X509_ACERT(b, a));
    emit_mem("pem.bytes", b);

    out_int("pem.write_bio.empty", PEM_write_bio_X509_ACERT(b, NULL));
    out_err("pem.write_bio.empty.err");

    {
        char *data = NULL;
        long n;

        BIO *w = BIO_new(BIO_s_mem());

        PEM_write_bio_X509_ACERT(w, a);
        n = BIO_get_mem_data(w, &data);
        {
            BIO *rb = BIO_new_mem_buf(data, (int)n);
            X509_ACERT *r = PEM_read_bio_X509_ACERT(rb, NULL, NULL, NULL);

            out_ptr("pem.read_bio", r);
            X509_ACERT_free(r);
            BIO_free(rb);
        }
        BIO_free(w);
    }

    {
        FILE *f = tmpfile();

        out_int("pem.write_fp", PEM_write_X509_ACERT(f, a));
        rewind(f);
        {
            X509_ACERT *r = PEM_read_X509_ACERT(f, NULL, NULL, NULL);

            out_ptr("pem.read_fp", r);
            X509_ACERT_free(r);
        }
        fclose(f);
    }

    BIO_free(b);
    X509_ACERT_free(a);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.3 -- `crypto/x509/x_ietfatt.c`.
 *
 * The two item groups, the value adder (including its mismatched-type and NULL refusals), the
 * `print` over a memory BIO, the DER round trip and the mixed-choice `d2i` refusal.
 * --------------------------------------------------------------------------------------------- */

static void drive_ietfatt(void)
{
    OSSL_IETF_ATTR_SYNTAX *ias = OSSL_IETF_ATTR_SYNTAX_new();
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    BIO *b = BIO_new(BIO_s_mem());

    ERR_clear_error();

    out_ptr("ietf.it", (const void *)OSSL_IETF_ATTR_SYNTAX_it());
    out_ptr("ietf.value_it", (const void *)OSSL_IETF_ATTR_SYNTAX_VALUE_it());
    out_ptr("ietf.new", ias);
    if (ias == NULL) {
        BIO_free(b);
        ASN1_OCTET_STRING_free(os);
        return;
    }
    {
        OSSL_IETF_ATTR_SYNTAX_VALUE *v = OSSL_IETF_ATTR_SYNTAX_VALUE_new();

        out_ptr("ietf.value_new", v);
        OSSL_IETF_ATTR_SYNTAX_VALUE_free(v);
        OSSL_IETF_ATTR_SYNTAX_VALUE_free(NULL);
        out_int("ietf.value_free", 1);
    }

    out_int("ietf.get_value_num.new", OSSL_IETF_ATTR_SYNTAX_get_value_num(ias));
    out_ptr("ietf.get0_policyAuthority.new",
            (const void *)OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(ias));
    {
        int t = -1;

        out_ptr("ietf.get0_value.new", OSSL_IETF_ATTR_SYNTAX_get0_value(ias, 0, &t));
        out_int("ietf.get0_value.new.type", t);
    }

    OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(ias, NULL);
    out_ptr("ietf.get0_policyAuthority.after",
            (const void *)OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(ias));

    ASN1_OCTET_STRING_set(os, (const unsigned char *)"abc", 3);
    out_int("ietf.add1_octets", OSSL_IETF_ATTR_SYNTAX_add1_value(ias, OSSL_IETFAS_OCTETS, os));
    out_int("ietf.get_value_num.1", OSSL_IETF_ATTR_SYNTAX_get_value_num(ias));
    {
        int t = -1;
        void *v = OSSL_IETF_ATTR_SYNTAX_get0_value(ias, 0, &t);

        out_ptr("ietf.get0_value.0", v);
        out_int("ietf.get0_value.0.type", t);
        out_int("ietf.get0_value.0.asn1_equal",
                v == (void *)OSSL_IETF_ATTR_SYNTAX_get0_value(ias, 0, NULL));
    }
    {
        int t = -1;

        out_ptr("ietf.get0_value.oob", OSSL_IETF_ATTR_SYNTAX_get0_value(ias, 5, &t));
    }

    ERR_clear_error();
    {
        ASN1_OCTET_STRING *os2 = ASN1_OCTET_STRING_new();

        ASN1_OCTET_STRING_set(os2, (const unsigned char *)"x", 1);
        out_int("ietf.add1_mismatch",
                OSSL_IETF_ATTR_SYNTAX_add1_value(ias, OSSL_IETFAS_OID, os2));
        out_err("ietf.add1_mismatch.err");
        ASN1_OCTET_STRING_free(os2);
    }
    out_int("ietf.add1_null", OSSL_IETF_ATTR_SYNTAX_add1_value(ias, OSSL_IETFAS_OCTETS, NULL));

    out_int("ietf.print", OSSL_IETF_ATTR_SYNTAX_print(b, ias, 2));
    emit_mem("ietf.print.out", b);

    {
        int len = i2d_OSSL_IETF_ATTR_SYNTAX(ias, NULL);
        unsigned char *der = OPENSSL_malloc(len);
        unsigned char *q = der;

        i2d_OSSL_IETF_ATTR_SYNTAX(ias, &q);
        out_int("ietf.i2d.len", len);
        out_hex("ietf.i2d", der, len);
        {
            const unsigned char *r = der;
            OSSL_IETF_ATTR_SYNTAX *back = d2i_OSSL_IETF_ATTR_SYNTAX(NULL, &r, len);

            out_ptr("ietf.d2i", back);
            out_int("ietf.d2i.count",
                    back != NULL ? OSSL_IETF_ATTR_SYNTAX_get_value_num(back) : -1);
            OSSL_IETF_ATTR_SYNTAX_free(back);
        }
        OPENSSL_free(der);
    }

    /* A sequence whose two values use different choices is refused by the hand-written d2i. */
    {
        static const unsigned char mixed[] = {
            0x30, 0x06, 0x04, 0x01, 0x61, 0x06, 0x01, 0x2a,
        };
        const unsigned char *r = mixed;

        ERR_clear_error();
        out_ptr("ietf.d2i.mixed", d2i_OSSL_IETF_ATTR_SYNTAX(NULL, &r, (long)sizeof mixed));
        out_err("ietf.d2i.mixed.err");
    }

    OSSL_IETF_ATTR_SYNTAX_free(ias);
    OSSL_IETF_ATTR_SYNTAX_free(NULL);
    out_int("ietf.free", 1);
    BIO_free(b);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.3 -- the `x_all.c` doors.
 *
 * The `X509_ACERT` and `X509_REQ` `_fp`/`_bio` stream faces over the two fixed DER fixtures, the
 * request digest, and the six sign/verify doors driven to their NULL-key refusals (a context is
 * supplied where the `_ctx` form needs one; no key is generated).
 * --------------------------------------------------------------------------------------------- */

static void drive_xall(void)
{
    X509_ACERT *a;
    X509_REQ *req;

    {
        const unsigned char *p = RT_X509_ACERT_DER;

        a = d2i_X509_ACERT(NULL, &p, (long)sizeof RT_X509_ACERT_DER);
    }
    out_ptr("xall.acert", a);
    if (a != NULL) {
        ERR_clear_error();
        {
            BIO *b = BIO_new_mem_buf(RT_X509_ACERT_DER, (int)sizeof RT_X509_ACERT_DER);
            X509_ACERT *r = d2i_X509_ACERT_bio(b, NULL);

            out_ptr("xall.acert.d2i_bio", r);
            X509_ACERT_free(r);
            BIO_free(b);
        }
        {
            BIO *b = BIO_new(BIO_s_mem());

            out_int("xall.acert.i2d_bio", i2d_X509_ACERT_bio(b, a));
            emit_mem("xall.acert.i2d_bio.out", b);
            BIO_free(b);
        }
        {
            FILE *f = tmpfile();

            fwrite(RT_X509_ACERT_DER, 1, sizeof RT_X509_ACERT_DER, f);
            rewind(f);
            {
                X509_ACERT *r = d2i_X509_ACERT_fp(f, NULL);

                out_ptr("xall.acert.d2i_fp", r);
                X509_ACERT_free(r);
            }
            fclose(f);
        }
        {
            FILE *f = tmpfile();

            out_int("xall.acert.i2d_fp", i2d_X509_ACERT_fp(f, a));
            fclose(f);
        }

        ERR_clear_error();
        out_int("xall.acert.verify", X509_ACERT_verify(a, NULL));
        out_err("xall.acert.verify.err");
        ERR_clear_error();
        out_int("xall.acert.sign", X509_ACERT_sign(a, NULL, NULL));
        {
            EVP_MD_CTX *ctx = mk_sig_ctx();

            ERR_clear_error();
            out_int("xall.acert.sign_ctx", X509_ACERT_sign_ctx(a, ctx));
            out_err("xall.acert.sign_ctx.err");
            EVP_MD_CTX_free(ctx);
        }
        X509_ACERT_free(a);
    }

    {
        const unsigned char *p = RT_X509_REQ_DER;

        req = d2i_X509_REQ(NULL, &p, (long)RT_X509_REQ_DER_LEN);
    }
    out_ptr("xall.req", req);
    if (req != NULL) {
        ERR_clear_error();
        {
            BIO *b = BIO_new_mem_buf(RT_X509_REQ_DER, (int)RT_X509_REQ_DER_LEN);
            X509_REQ *r = d2i_X509_REQ_bio(b, NULL);

            out_ptr("xall.req.d2i_bio", r);
            X509_REQ_free(r);
            BIO_free(b);
        }
        {
            BIO *b = BIO_new(BIO_s_mem());

            out_int("xall.req.i2d_bio", i2d_X509_REQ_bio(b, req));
            {
                char *data = NULL;
                long n = BIO_get_mem_data(b, &data);

                out_int("xall.req.i2d_bio.len", n);
                out_int("xall.req.i2d_bio.equals_fixture",
                        n == (long)RT_X509_REQ_DER_LEN
                            && data != NULL
                            && memcmp(data, RT_X509_REQ_DER, (size_t)n) == 0);
                out_hex("xall.req.i2d_bio.hex", (const unsigned char *)data, n);
            }
            BIO_free(b);
        }
        {
            FILE *f = tmpfile();

            fwrite(RT_X509_REQ_DER, 1, RT_X509_REQ_DER_LEN, f);
            rewind(f);
            {
                X509_REQ *r = d2i_X509_REQ_fp(f, NULL);

                out_ptr("xall.req.d2i_fp", r);
                X509_REQ_free(r);
            }
            fclose(f);
        }
        {
            FILE *f = tmpfile();

            out_int("xall.req.i2d_fp", i2d_X509_REQ_fp(f, req));
            fclose(f);
        }
        {
            unsigned char md[EVP_MAX_MD_SIZE];
            unsigned int mdlen = 0;
            int rv;

            memset(md, 0, sizeof md);
            rv = X509_REQ_digest(req, EVP_sha256(), md, &mdlen);
            out_int("xall.req.digest", rv);
            out_int("xall.req.digest.len", (long)mdlen);
            out_hex("xall.req.digest.md", md, (long)mdlen);
        }
        ERR_clear_error();
        out_int("xall.req.verify", X509_REQ_verify(req, NULL));
        out_err("xall.req.verify.err");
        ERR_clear_error();
        out_int("xall.req.verify_ex", X509_REQ_verify_ex(req, NULL, NULL, NULL));
        out_err("xall.req.verify_ex.err");
        X509_REQ_free(req);
    }

    {
        X509_REQ *fresh = X509_REQ_new();

        out_ptr("xall.req.fresh", fresh);
        if (fresh != NULL) {
            out_int("xall.req.sign", X509_REQ_sign(fresh, NULL, NULL));
            {
                EVP_MD_CTX *ctx = mk_sig_ctx();

                ERR_clear_error();
                out_int("xall.req.sign_ctx", X509_REQ_sign_ctx(fresh, ctx));
                out_err("xall.req.sign_ctx.err");
                EVP_MD_CTX_free(ctx);
            }
            X509_REQ_free(fresh);
        }
    }
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.7 -- `crypto/x509/t_acert.c`: the two attribute-certificate printers.
 *
 * Both write to a memory BIO and are reduced to the exact length and digest of the text they
 * produced; `X509_ACERT_print` is the `XN_FLAG_COMPAT`/`X509_FLAG_COMPAT` spelling and
 * `X509_ACERT_print_ex` is driven with multiline names and no sigdump suppression.
 * --------------------------------------------------------------------------------------------- */

static void drive_acert_print(void)
{
    const unsigned char *p = RT_X509_ACERT_DER;
    X509_ACERT *a = d2i_X509_ACERT(NULL, &p, (long)sizeof RT_X509_ACERT_DER);
    BIO *b;

    out_ptr("acert.print.acert", a);
    if (a == NULL)
        return;

    b = BIO_new(BIO_s_mem());
    out_int("acert.print.ret", X509_ACERT_print(b, a));
    out_mem("acert.print", b);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    out_int("acert.print_ex.ret",
            X509_ACERT_print_ex(b, a, XN_FLAG_SEP_MULTILINE | XN_FLAG_FN_LN, 0));
    out_mem("acert.print_ex", b);
    BIO_free(b);

    /* A suppressed-signature spelling: the sigdump arm is skipped. */
    b = BIO_new(BIO_s_mem());
    out_int("acert.print_nosig.ret",
            X509_ACERT_print_ex(b, a, XN_FLAG_COMPAT, X509_FLAG_NO_SIGDUMP));
    out_mem("acert.print_nosig", b);
    BIO_free(b);

    X509_ACERT_free(a);
}

int main(void)
{
    ERR_clear_error();

    drive_acert_items();
    drive_acert_setters();
    drive_acert_attrs();
    drive_acert_pem();
    drive_ietfatt();
    drive_xall();
    drive_acert_print();

    return 0;
}
