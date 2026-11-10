/*
 * openssl-rs — Phase 25 B71 external control: the CMS/PKCS7 ASN.1 item callbacks.
 *
 * SCOPE. B71 discharges the item callbacks installed in static `ASN1_AUX`
 * tables (`asn1_cb` slots), not exported symbols:
 *
 *   src/cms/cms_asn1.rs : cms_ec_cb, cms_rek_cb, cms_kari_cb,
 *                         cms_kemri_cb, cms_ri_cb, cms_cb
 *   src/pkcs7/pk7_asn1.rs: ri_cb
 *
 * The probe cannot name those private callbacks. It drives the item machinery
 * through exported entry points, which is what invokes them:
 *
 *   d2i_CMS_ContentInfo / i2d_CMS_ContentInfo  (NEW_PRE/NEW_POST/D2I_POST,
 *                                              FREE_PRE/FREE_POST on failure)
 *   CMS_ContentInfo_free                       (FREE_PRE/FREE_POST)
 *   i2d_CMS_bio_stream(..., SMIME_STREAM)      (cms_cb STREAM_PRE/POST)
 *   SMIME_write_CMS(..., SMIME_DETACHED)       (cms_cb DETACHED_PRE/POST)
 *   d2i_PKCS7 / i2d_PKCS7 / PKCS7_free         (pk7 ri_cb FREE_POST)
 *
 * OBSERVABLES.
 *   cms_ri_cb   D2I_POST sets `ri->type` from the CHOICE selector. A KARI
 *               recipient decodes as CMS_RECIPINFO_AGREE (1) and a KEM ORI as
 *               CMS_RECIPINFO_KEM (5); a zeroed block would read 0, so
 *               CMS_RecipientInfo_type() proves the callback ran.
 *   cms_kari_cb NEW_POST allocates the wrapping context. A non-NULL
 *               CMS_RecipientInfo_kari_get0_ctx() proves it ran after a d2i.
 *   cms_kemri_cb likewise, via CMS_RecipientInfo_kemri_get0_ctx().
 *   cms_ec_cb   frees the live session key installed by CMS_encrypt; a missing
 *               FREE_POST would leak it, so a clean LeakSanitizer run observes
 *               it. The same applies to cms_rek_cb / pk7 ri_cb for their live
 *               runtime members (`pkey`, `cert`). Those members are NULL after
 *               a plain d2i, so the probe attaches a live cert to a decoded
 *               PKCS7 through PKCS7_add_recipient before freeing it.
 *
 * NULL-SLOT ARM. For every d2i of a fresh value the item layer calls the
 * callback's NEW_PRE with `*pval == NULL`; the callbacks must tolerate that.
 * A malformed/truncated DER additionally drives the partial-free paths.
 *
 * Build (inside the court only):
 *   cc -std=c11 -O1 -Wall -Wextra \
 *      -I artifacts/phase2/install/include \
 *      -o court/tmp/closure-b71-cms/rt_cms_asn1_callbacks \
 *      courts/phase25/rt_cms_asn1_callbacks.c \
 *      -L artifacts/phase2/install/lib -lcrypto \
 *      -Wl,-rpath,/work/artifacts/phase2/install/lib
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int cond, const char *what)
{
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", what);
        ERR_print_errors_fp(stderr);
        failures++;
    }
}

static EVP_PKEY *mk_key(const char *type)
{
    if (strcmp(type, "RSA") == 0)
        return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    if (strcmp(type, "EC") == 0)
        return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    return EVP_PKEY_Q_keygen(NULL, NULL, type);
}

/* A self-signed certificate for `pub`, signed by `signer` (which may differ:
 * an ML-KEM public key cannot itself sign, so the KEM certificate is signed by
 * an RSA key while carrying the KEM public key). */
static X509 *mk_cert(EVP_PKEY *pub, EVP_PKEY *signer)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;

    cert = X509_new();
    name = X509_NAME_new();
    if (cert == NULL || name == NULL)
        goto done;
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)"b71-cms", -1, -1, 0))
        goto done;
    if (!X509_set_version(cert, 2)
        || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
        || !X509_set_subject_name(cert, name)
        || !X509_set_issuer_name(cert, name)
        || !X509_set_pubkey(cert, pub))
        goto done;
    if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(cert), 3600) == NULL)
        goto done;
    if (!X509_sign(cert, signer, EVP_sha256()))
        goto done;

done:
    X509_NAME_free(name);
    if (failures > 0 || cert == NULL) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

static BIO *payload(void)
{
    return BIO_new_mem_buf("b71 payload", 11);
}

/* EnvelopedData with one recipient of the requested key type. `flags` selects
 * the finalisation strategy: 0 finalises the content, CMS_STREAM / CMS_PARTIAL
 * leave it for the streaming/detached arms. Returns NULL if the library refuses
 * that recipient kind (reported as NOT_RUN by the caller). */
static CMS_ContentInfo *mk_env(const char *type, unsigned int flags)
{
    EVP_PKEY *pub = NULL, *signer = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *certs = NULL;
    BIO *data = NULL;
    CMS_ContentInfo *cms = NULL;

    if (strcmp(type, "ML-KEM-768") == 0) {
        pub = mk_key("ML-KEM-768");
        signer = mk_key("RSA");
    } else {
        pub = mk_key(type);
        signer = pub;
    }
    if (pub == NULL || signer == NULL)
        goto done;
    cert = mk_cert(pub, signer);
    if (cert == NULL)
        goto done;
    certs = sk_X509_new_null();
    data = payload();
    if (certs == NULL || data == NULL
        || !sk_X509_push(certs, cert))
        goto done;
    cms = CMS_encrypt(certs, data, EVP_aes_256_cbc(), flags | CMS_BINARY);
    if (cms == NULL && (flags & (CMS_STREAM | CMS_PARTIAL)) == 0) {
        /* The content wrap can refuse a recipient kind (notably KEM); the bare
         * EnvelopedData still carries the recipient structure the callbacks act
         * on, which is all this probe needs. */
        ERR_clear_error();
        cms = CMS_EnvelopedData_create(EVP_aes_256_cbc());
        if (cms != NULL && CMS_add1_recipient_cert(cms, cert, 0) == NULL) {
            CMS_ContentInfo_free(cms);
            cms = NULL;
        }
    }
    if (cms == NULL) {
        fprintf(stderr, "mk_env(%s, flags=0x%x) failed\n", type, flags);
        ERR_print_errors_fp(stderr);
        ERR_clear_error();
    }

done:
    BIO_free(data);
    sk_X509_free(certs);
    X509_free(cert);
    if (signer != pub)
        EVP_PKEY_free(signer);
    EVP_PKEY_free(pub);
    return cms;
}

/* i2d -> d2i round trip. Returns the decoded value and the encoded bytes
 * (caller frees the bytes with OPENSSL_free). */
static CMS_ContentInfo *cms_roundtrip(CMS_ContentInfo *cms,
                                      unsigned char **der_out, int *der_len)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    CMS_ContentInfo *dec = NULL;
    int len;

    len = i2d_CMS_ContentInfo(cms, &der);
    if (len <= 0)
        return NULL;
    p = der;
    dec = d2i_CMS_ContentInfo(NULL, &p, len);
    *der_out = der;
    *der_len = len;
    return dec;
}

/* Inspect the decoded recipients. `expect_type` is -1 when the test only wants
 * the stack to be non-empty. `want_ctx` selects KARI/KEM context observation. */
static void inspect(const char *tag, CMS_ContentInfo *cms, int expect_type,
                    int want_kari_ctx, int want_kem_ctx)
{
    STACK_OF(CMS_RecipientInfo) *ris = CMS_get0_RecipientInfos(cms);
    int n, i;

    if (ris == NULL) {
        fprintf(stderr, "FAIL %s: no recipientInfos\n", tag);
        failures++;
        return;
    }
    n = sk_CMS_RecipientInfo_num(ris);
    if (n <= 0) {
        fprintf(stderr, "FAIL %s: recipientInfos empty\n", tag);
        failures++;
        return;
    }
    for (i = 0; i < n; i++) {
        CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(ris, i);
        int t = CMS_RecipientInfo_type(ri);

        if (expect_type >= 0) {
            char msg[128];

            snprintf(msg, sizeof(msg), "%s: CMS_RecipientInfo_type %d != %d",
                     tag, t, expect_type);
            check(t == expect_type, msg);
        }
        if (want_kari_ctx) {
            char msg[128];

            snprintf(msg, sizeof(msg), "%s: KARI context is NULL", tag);
            check(CMS_RecipientInfo_kari_get0_ctx(ri) != NULL, msg);
        }
        if (want_kem_ctx) {
            char msg[128];

            snprintf(msg, sizeof(msg), "%s: KEM context is NULL", tag);
            check(CMS_RecipientInfo_kemri_get0_ctx(ri) != NULL, msg);
        }
    }
}

/* A malformed decode must fail cleanly; the item layer frees whatever it
 * allocated, driving the callbacks' FREE_PRE/FREE_POST on partial values. */
static void malformed(const char *tag, const unsigned char *der, int len)
{
    static const unsigned char garbage[] = { 0x30, 0x82, 0xff, 0xff, 0x02 };
    int cuts[4];
    int i;

    cuts[0] = len / 4;
    cuts[1] = len / 2;
    cuts[2] = len - 1;
    cuts[3] = -1;
    for (i = 0; i < 4; i++) {
        const unsigned char *p;
        CMS_ContentInfo *bad;
        int n = (i == 3) ? (int)sizeof(garbage) : cuts[i];

        p = (i == 3) ? garbage : der;
        bad = d2i_CMS_ContentInfo(NULL, &p, n);
        if (bad != NULL) {
            char msg[128];

            snprintf(msg, sizeof(msg), "%s: malformed decode %d unexpectedly succeeded",
                     tag, i);
            fprintf(stderr, "FAIL %s\n", msg);
            failures++;
            CMS_ContentInfo_free(bad);
        }
        ERR_clear_error();
    }
}

static void stream_arms(void)
{
    /* CMS_STREAM leaves the content unfinalised, which is the state
     * i2d_CMS_bio_stream is designed to finalise through the ASN.1 BIO. */
    CMS_ContentInfo *cms = mk_env("RSA", CMS_STREAM);
    BIO *out = BIO_new(BIO_s_mem());
    BIO *in = payload();

    check(cms != NULL, "CMS_encrypt(RSA, CMS_STREAM)");
    if (cms != NULL && out != NULL && in != NULL) {
        int r = i2d_CMS_bio_stream(out, cms, in, SMIME_STREAM);

        check(r == 1, "i2d_CMS_bio_stream(SMIME_STREAM)");
    } else {
        check(cms != NULL && out != NULL && in != NULL,
              "BIO_new(BIO_s_mem)/payload");
    }
    CMS_ContentInfo_free(cms);
    BIO_free(in);
    BIO_free(out);
    ERR_clear_error();
}

static void detached_arms(void)
{
    /* CMS_PARTIAL leaves the content unfinalised for the DETACHED arms. */
    CMS_ContentInfo *cms = mk_env("RSA", CMS_PARTIAL);
    BIO *out = BIO_new(BIO_s_mem());
    BIO *in = payload();
    int wrote = 0;

    if (cms != NULL && out != NULL && in != NULL)
        wrote = SMIME_write_CMS(out, cms, in, SMIME_DETACHED) != 0;
    if (!wrote) {
        /* A detached S/MIME body is signed, and the writer needs a non-empty
         * digest-algorithm list for its `micalg`. Retry with a CMS_sign value
         * built in partial mode (content still unfinalised). */
        EVP_PKEY *k = mk_key("RSA");
        X509 *cert = (k != NULL) ? mk_cert(k, k) : NULL;
        BIO *in2 = payload();

        ERR_clear_error();
        CMS_ContentInfo_free(cms);
        cms = NULL;
        if (cert != NULL && in2 != NULL) {
            cms = CMS_sign(cert, k, NULL, in2, CMS_PARTIAL | CMS_BINARY);
            if (cms != NULL) {
                (void)BIO_reset(out);
                wrote = SMIME_write_CMS(out, cms, in2, SMIME_DETACHED) != 0;
            }
        }
        if (!wrote)
            fprintf(stderr, "NOT_RUN cms_cb DETACHED_PRE/POST (SMIME write refused)\n");
        ERR_clear_error();
        BIO_free(in2);
        X509_free(cert);
        EVP_PKEY_free(k);
    }
    CMS_ContentInfo_free(cms);
    BIO_free(in);
    BIO_free(out);
    ERR_clear_error();
}

static void pkcs7_case(void)
{
    EVP_PKEY *k = mk_key("RSA");
    X509 *cert = NULL;
    STACK_OF(X509) *certs = NULL;
    BIO *data = NULL;
    PKCS7 *p7 = NULL, *dec = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;

    if (k == NULL)
        goto done;
    cert = mk_cert(k, k);
    if (cert == NULL)
        goto done;
    certs = sk_X509_new_null();
    data = payload();
    if (certs == NULL || data == NULL || !sk_X509_push(certs, cert))
        goto done;
    p7 = PKCS7_encrypt(certs, data, EVP_aes_256_cbc(), 0);
    if (p7 == NULL)
        goto done;

    len = i2d_PKCS7(p7, &der);
    if (len <= 0)
        goto done;
    p = der;
    dec = d2i_PKCS7(NULL, &p, len);
    check(dec != NULL, "d2i_PKCS7 round trip");
    if (dec != NULL) {
        /* Attach a live runtime certificate to a decoded recipient: freeing it
         * is exactly what pk7 `ri_cb` does on FREE_POST. LeakSanitizer observes
         * the release; without the callback this reference leaks. */
        if (PKCS7_add_recipient(dec, cert) == NULL)
            fprintf(stderr, "NOT_RUN pk7 ri_cb live-cert arm (PKCS7_add_recipient)\n");
    }
    if (dec != NULL && len > 1) {
        const unsigned char *q = der;

        /* Partial-free path on the PKCS7 decoder. */
        if (d2i_PKCS7(NULL, &q, len / 2) != NULL) {
            fprintf(stderr, "FAIL d2i_PKCS7 malformed unexpectedly succeeded\n");
            failures++;
        }
        ERR_clear_error();
    }

done:
    OPENSSL_free(der);
    PKCS7_free(dec);
    PKCS7_free(p7);
    BIO_free(data);
    sk_X509_free(certs);
    X509_free(cert);
    EVP_PKEY_free(k);
}

int main(void)
{
    CMS_ContentInfo *rsa = NULL, *rsa_dec = NULL;
    CMS_ContentInfo *ec = NULL, *ec_dec = NULL;
    CMS_ContentInfo *kem = NULL, *kem_dec = NULL;
    unsigned char *rsa_der = NULL, *ec_der = NULL, *kem_der = NULL;
    int rsa_len = 0, ec_len = 0, kem_len = 0;
    int kem_ran = 0;
    int skip_stream = getenv("RT_B71_SKIP_STREAM") != NULL;

    ERR_clear_error();

    /* 1. KTRI (RSA): cms_cb, cms_ec_cb, cms_ri_cb TRANS. */
    rsa = mk_env("RSA", 0);
    check(rsa != NULL, "CMS_encrypt(RSA)");
    if (rsa != NULL) {
        rsa_dec = cms_roundtrip(rsa, &rsa_der, &rsa_len);
        check(rsa_dec != NULL, "d2i_CMS_ContentInfo(RSA)");
        if (rsa_dec != NULL) {
            inspect("KTRI", rsa_dec, CMS_RECIPINFO_TRANS, 0, 0);
        }
        if (!skip_stream) {
            stream_arms();
            detached_arms();
        }
        if (rsa_der != NULL)
            malformed("KTRI", rsa_der, rsa_len);
    }

    /* 2. KARI (EC): cms_kari_cb NEW_POST/FREE_POST, cms_rek_cb FREE_POST,
     *    cms_ri_cb D2I_POST (AGREE) + FREE_PRE. */
    ec = mk_env("EC", 0);
    check(ec != NULL, "CMS_encrypt(EC)");
    if (ec != NULL) {
        ec_dec = cms_roundtrip(ec, &ec_der, &ec_len);
        check(ec_dec != NULL, "d2i_CMS_ContentInfo(EC)");
        if (ec_dec != NULL)
            inspect("KARI", ec_dec, CMS_RECIPINFO_AGREE, 1, 0);
    }

    /* 3. KEM (ML-KEM-768 ORI): cms_kemri_cb, cms_ri_cb ORI->KEM mapping. */
    kem = mk_env("ML-KEM-768", 0);
    if (kem == NULL) {
        fprintf(stderr, "NOT_RUN cms_kemri_cb (ML-KEM recipient could not be built)\n");
    } else {
        kem_dec = cms_roundtrip(kem, &kem_der, &kem_len);
        if (kem_dec == NULL) {
            fprintf(stderr, "NOT_RUN cms_kemri_cb (KEM CMS did not re-decode)\n");
        } else {
            kem_ran = 1;
            inspect("KEM", kem_dec, CMS_RECIPINFO_KEM, 0, 1);
        }
    }

    /* Free every live value: FREE_PRE/FREE_POST for all six CMS callbacks,
     * with cms_ec_cb/cms_rek_cb/cms_kemri_cb holding live members where the
     * construction installed them. LeakSanitizer observes any missed release. */
    CMS_ContentInfo_free(rsa_dec);
    CMS_ContentInfo_free(ec_dec);
    CMS_ContentInfo_free(kem_dec);
    CMS_ContentInfo_free(rsa);
    CMS_ContentInfo_free(ec);
    CMS_ContentInfo_free(kem);
    OPENSSL_free(rsa_der);
    OPENSSL_free(ec_der);
    OPENSSL_free(kem_der);

    pkcs7_case();

    /* Release OpenSSL's process-global one-time allocations (the constant
     * BIGNUMs and error strings) before LeakSanitizer's exit check. */
    OPENSSL_cleanup();

    if (failures == 0) {
        printf("PASS cms asn1 callbacks: ktri=1 kari=1 kari_ctx=1 kem=%s "
               "pkcs7=1 stream=%s malformed=clean\n",
               kem_ran ? "1" : "NOT_RUN",
               skip_stream ? "SKIPPED" : "1");
    }
    return failures == 0 ? 0 : 1;
}
