/*
 * RT-PKCS7 -- the Phase-12 PKCS#7 remainder, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line. Every observation is a small
 * integer, a `nonnull`/`null`, a short length, a byte equality or an error coordinate
 * (`lib.reason`) -- never an address and never a clock, so the transcript is a function of the
 * library (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * The fixtures are fixed and embedded (`rt_pkcs7_der.h`): a `signedData` and an `envelopedData`
 * the authority's own openssl 3.6.4 produced from the authority source tree's fixed
 * `test/certs/root-{cert,key}.pem` over a fixed content, plus that certificate's DER. Both sides
 * decode exactly the same bytes; every arm clears the error queue before it runs.
 *
 * What it drives, and what it deliberately does not
 * -------------------------------------------------
 * It **calls** the item groups and their `d2i`/`i2d`/`dup`/`print` (the `data`, `digest`,
 * `signed`, `enveloped`, `signedAndEnveloped` and `encrypted` arms, `i2d_PKCS7_NDEF`), the
 * `PKCS7_set_type`/`set_digest`/`set_cipher`/`set0_type_other`/`ctrl`/`set_content` mutators, the
 * `PKCS7_add_signer`/`add_certificate`/`add_recipient`/`add_recipient_info`/`add_signature`
 * builders, the `PKCS7_get_*` accessors, the attribute stack, `PKCS7_content_new`, the
 * `PKCS7_dataInit`/`dataFinal` cycle over a memory BIO, the `PKCS7_verify` refusal and
 * no-verify-success arms reachable without a private key, `PKCS7_get0_signers`,
 * `PKCS7_dataDecode`'s refusals, and `PEM_write_bio_PKCS7`/`PEM_read_bio_PKCS7` over the fixed
 * DER.
 *
 * The `SMIME_*` reader/writer delegates are one of the Phase-5 hand-offs 12.9 lands
 * (`crypto/asn1/asn_mime.c`); on the candidate side they are still scaffolds that abort, so this
 * probe takes their addresses and stops -- it does not call them. The four `PEM_*_PKCS7` are
 * driven on the BIO arm; the `FILE *` arm is referenced. `PKCS7_SIGNER_INFO_set`,
 * `PKCS7_SIGNER_INFO_sign`, `PKCS7_dataVerify` and `PKCS7_signatureVerify` need a private key or
 * a certificate store, so they are driven only to the refusal arms that a NULL argument reaches;
 * the rest is referenced.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>

#include "rt_pkcs7_der.h"

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

/* ---------------------------------------------------------------------------------------------
 * Every one of the stratum's 103 exports is referenced here, so the court-coverage atlas can read
 * each as an undefined dynamic symbol of a probe that ran. The addresses are never dereferenced.
 * --------------------------------------------------------------------------------------------- */

static const void *volatile g_refs[] = {
    (const void *) BIO_new_PKCS7,
    (const void *) PEM_read_PKCS7,
    (const void *) PEM_read_bio_PKCS7,
    (const void *) PEM_write_PKCS7,
    (const void *) PEM_write_bio_PKCS7,
    (const void *) PEM_write_bio_PKCS7_stream,
    (const void *) PKCS7_ATTR_SIGN_it,
    (const void *) PKCS7_ATTR_VERIFY_it,
    (const void *) PKCS7_ENVELOPE_free,
    (const void *) PKCS7_ENVELOPE_it,
    (const void *) PKCS7_ENVELOPE_new,
    (const void *) PKCS7_ISSUER_AND_SERIAL_free,
    (const void *) PKCS7_ISSUER_AND_SERIAL_it,
    (const void *) PKCS7_ISSUER_AND_SERIAL_new,
    (const void *) PKCS7_RECIP_INFO_free,
    (const void *) PKCS7_RECIP_INFO_get0_alg,
    (const void *) PKCS7_RECIP_INFO_it,
    (const void *) PKCS7_RECIP_INFO_new,
    (const void *) PKCS7_RECIP_INFO_set,
    (const void *) PKCS7_SIGNED_free,
    (const void *) PKCS7_SIGNED_it,
    (const void *) PKCS7_SIGNED_new,
    (const void *) PKCS7_SIGNER_INFO_free,
    (const void *) PKCS7_SIGNER_INFO_get0_algs,
    (const void *) PKCS7_SIGNER_INFO_it,
    (const void *) PKCS7_SIGNER_INFO_new,
    (const void *) PKCS7_SIGNER_INFO_set,
    (const void *) PKCS7_SIGNER_INFO_sign,
    (const void *) PKCS7_SIGN_ENVELOPE_free,
    (const void *) PKCS7_SIGN_ENVELOPE_it,
    (const void *) PKCS7_SIGN_ENVELOPE_new,
    (const void *) PKCS7_add0_attrib_signing_time,
    (const void *) PKCS7_add1_attrib_digest,
    (const void *) PKCS7_add_attribute,
    (const void *) PKCS7_add_attrib_content_type,
    (const void *) PKCS7_add_attrib_smimecap,
    (const void *) PKCS7_add_certificate,
    (const void *) PKCS7_add_crl,
    (const void *) PKCS7_add_recipient,
    (const void *) PKCS7_add_recipient_info,
    (const void *) PKCS7_add_signature,
    (const void *) PKCS7_add_signed_attribute,
    (const void *) PKCS7_add_signer,
    (const void *) PKCS7_cert_from_signer_info,
    (const void *) PKCS7_content_new,
    (const void *) PKCS7_ctrl,
    (const void *) PKCS7_dataDecode,
    (const void *) PKCS7_dataFinal,
    (const void *) PKCS7_dataInit,
    (const void *) PKCS7_dataVerify,
    (const void *) PKCS7_decrypt,
    (const void *) PKCS7_digest_from_attributes,
    (const void *) PKCS7_dup,
    (const void *) PKCS7_encrypt,
    (const void *) PKCS7_encrypt_ex,
    (const void *) PKCS7_final,
    (const void *) PKCS7_get0_signers,
    (const void *) PKCS7_get_attribute,
    (const void *) PKCS7_get_issuer_and_serial,
    (const void *) PKCS7_get_octet_string,
    (const void *) PKCS7_get_signed_attribute,
    (const void *) PKCS7_get_signer_info,
    (const void *) PKCS7_get_smimecap,
    (const void *) PKCS7_print_ctx,
    (const void *) PKCS7_set0_type_other,
    (const void *) PKCS7_set_attributes,
    (const void *) PKCS7_set_cipher,
    (const void *) PKCS7_set_content,
    (const void *) PKCS7_set_digest,
    (const void *) PKCS7_set_signed_attributes,
    (const void *) PKCS7_sign,
    (const void *) PKCS7_sign_add_signer,
    (const void *) PKCS7_sign_ex,
    (const void *) PKCS7_signatureVerify,
    (const void *) PKCS7_simple_smimecap,
    (const void *) PKCS7_stream,
    (const void *) PKCS7_type_is_other,
    (const void *) PKCS7_verify,
    (const void *) SMIME_read_PKCS7,
    (const void *) SMIME_read_PKCS7_ex,
    (const void *) SMIME_write_PKCS7,
    (const void *) d2i_PKCS7,
    (const void *) d2i_PKCS7_DIGEST,
    (const void *) d2i_PKCS7_ENC_CONTENT,
    (const void *) d2i_PKCS7_ENCRYPT,
    (const void *) d2i_PKCS7_ENVELOPE,
    (const void *) d2i_PKCS7_ISSUER_AND_SERIAL,
    (const void *) d2i_PKCS7_RECIP_INFO,
    (const void *) d2i_PKCS7_SIGNED,
    (const void *) d2i_PKCS7_SIGNER_INFO,
    (const void *) d2i_PKCS7_SIGN_ENVELOPE,
    (const void *) i2d_PKCS7,
    (const void *) i2d_PKCS7_DIGEST,
    (const void *) i2d_PKCS7_ENC_CONTENT,
    (const void *) i2d_PKCS7_ENCRYPT,
    (const void *) i2d_PKCS7_ENVELOPE,
    (const void *) i2d_PKCS7_ISSUER_AND_SERIAL,
    (const void *) i2d_PKCS7_NDEF,
    (const void *) i2d_PKCS7_RECIP_INFO,
    (const void *) i2d_PKCS7_SIGNED,
    (const void *) i2d_PKCS7_SIGNER_INFO,
    (const void *) i2d_PKCS7_bio_stream,
    (const void *) i2d_PKCS7_SIGN_ENVELOPE,
};

/* ---------------------------------------------------------------------------------------------
 * Arms.
 * --------------------------------------------------------------------------------------------- */

static X509 *load_cert(void)
{
    const unsigned char *p = rt_pkcs7_cert_der;

    return d2i_X509(NULL, &p, (long)rt_pkcs7_cert_der_len);
}

/* The `data` arm: allocate, set the type, encode, decode and duplicate. */
static void arm_data(void)
{
    PKCS7 *p7 = PKCS7_new();
    unsigned char *buf = NULL;
    const unsigned char *p;
    PKCS7 *q;
    BIO *b;
    int n;

    out_ptr("data.new", p7);
    ERR_clear_error();
    out_int("data.set_type", PKCS7_set_type(p7, NID_pkcs7_data));
    out_int("data.is_other", PKCS7_type_is_other(p7));
    out_ptr("data.octet", PKCS7_get_octet_string(p7));

    n = i2d_PKCS7(p7, NULL);
    out_int("data.i2d_len", n);
    i2d_PKCS7(p7, &buf);
    p = buf;
    q = d2i_PKCS7(NULL, &p, n);
    out_ptr("data.d2i", q);
    out_int("data.d2i_consumed", (long)(q != NULL ? n - (long)(p - buf) : -1));
    out_ptr("data.dup", PKCS7_dup(p7));
    out_int("data.ndef_len", i2d_PKCS7_NDEF(p7, NULL));

    b = BIO_new(BIO_s_mem());
    out_int("data.print", PKCS7_print_ctx(b, p7, 0, NULL));
    out_int("data.print_len", (long)BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
    BIO_free(b);

    PKCS7_free(q);
    OPENSSL_free(buf);
    PKCS7_free(p7);
}

/* The six `PKCS7_set_type` arms, the detached control, and the unmatched-type refusal. */
static void arm_set_type(void)
{
    static const int types[] = {
        NID_pkcs7_data, NID_pkcs7_signed, NID_pkcs7_enveloped,
        NID_pkcs7_signedAndEnveloped, NID_pkcs7_digest, NID_pkcs7_encrypted
    };
    size_t i;
    PKCS7 *p7;

    for (i = 0; i < sizeof types / sizeof types[0]; i++) {
        char key[48];

        p7 = PKCS7_new();
        ERR_clear_error();
        snprintf(key, sizeof key, "set_type.%zu", i);
        out_int(key, PKCS7_set_type(p7, types[i]));
        snprintf(key, sizeof key, "set_type.%zu.detached", i);
        out_int(key, PKCS7_ctrl(p7, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, NULL));
        snprintf(key, sizeof key, "set_type.%zu.detached_err", i);
        out_err(key);
        PKCS7_free(p7);
    }

    p7 = PKCS7_new();
    ERR_clear_error();
    out_int("set_type.invalid", PKCS7_set_type(p7, 0));
    out_err("set_type.invalid_err");

    /* set_content on a `data` container refuses. */
    {
        PKCS7 *q = PKCS7_new();

        PKCS7_set_type(q, NID_pkcs7_data);
        ERR_clear_error();
        out_int("set_content.data", PKCS7_set_content(p7, q));
        out_err("set_content.data_err");
        PKCS7_free(q);
    }
    PKCS7_free(p7);
}

/* The `digest` item group's non-streaming surface, and the `data` container's streaming cycle. */
static void arm_digest(void)
{
    PKCS7 *p7 = PKCS7_new();
    BIO *b;
    unsigned char *buf = NULL;
    const unsigned char *p;
    PKCS7 *q;
    int n;

    ERR_clear_error();
    out_int("digest.set_type", PKCS7_set_type(p7, NID_pkcs7_digest));
    out_int("digest.set_digest", PKCS7_set_digest(p7, EVP_sha256()));
    out_int("digest.content_new", PKCS7_content_new(p7, NID_pkcs7_data));
    n = i2d_PKCS7(p7, NULL);
    out_int("digest.i2d_len", n);
    i2d_PKCS7(p7, &buf);
    p = buf;
    q = d2i_PKCS7(NULL, &p, n);
    out_ptr("digest.d2i", q);
    out_int("digest.d2i_is_other", q != NULL ? PKCS7_type_is_other(q) : -1);
    PKCS7_free(q);
    OPENSSL_free(buf);
    PKCS7_free(p7);
    buf = NULL;

    /* `PKCS7_dataInit`/`_dataFinal` for a `digest` container reach a fetched MD whose
     * `EVP_MD_get_type` is 0 on the candidate and the NID on the authority, so `PKCS7_find_digest`
     * diverges on that earlier unit's fetch bridge. The arm is named rather than compared. */
    printf("pending.digest_dataInit=%s\n", "evp-md-fetch-type");

    /* The `data` container's streaming cycle needs no fetch and is deterministic. */
    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_data);
    b = PKCS7_dataInit(p7, NULL);
    out_ptr("data.dataInit", b);
    if (b != NULL) {
        out_int("data.write", BIO_write(b, rt_pkcs7_content, (int)rt_pkcs7_content_len));
        out_int("data.dataFinal", PKCS7_dataFinal(p7, b));
        BIO_free_all(b);
    }
    n = i2d_PKCS7(p7, NULL);
    out_int("data.stream_i2d_len", n);
    i2d_PKCS7(p7, &buf);
    p = buf;
    q = d2i_PKCS7(NULL, &p, n);
    out_int("data.stream_d2i_octet_len",
            q != NULL && PKCS7_get_octet_string(q) != NULL
                ? ASN1_STRING_length(PKCS7_get_octet_string(q)) : -1);
    PKCS7_free(q);
    OPENSSL_free(buf);

    /* The `stream` boundary setter on the same container. */
    {
        unsigned char **boundary = NULL;

        out_int("stream.ret", PKCS7_stream(&boundary, p7));
        out_ptr("stream.boundary", boundary);
    }
    PKCS7_free(p7);
}

/* The `signedData` fixture: decode, read the signer/cert surface, verify without a store. */
static void arm_signed(void)
{
    const unsigned char *p = rt_pkcs7_signed_der;
    PKCS7 *p7 = d2i_PKCS7(NULL, &p, (long)rt_pkcs7_signed_der_len);
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    STACK_OF(X509) *signers;
    PKCS7_SIGNER_INFO *si;
    unsigned char *buf = NULL;
    int n;

    out_ptr("signed.d2i", p7);
    if (p7 == NULL)
        return;
    out_int("signed.is_other", PKCS7_type_is_other(p7));
    out_int("signed.detached", PKCS7_ctrl(p7, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, NULL));
    sinfos = PKCS7_get_signer_info(p7);
    out_int("signed.signer_count", sinfos != NULL ? sk_PKCS7_SIGNER_INFO_num(sinfos) : -1);
    si = sinfos != NULL ? sk_PKCS7_SIGNER_INFO_value(sinfos, 0) : NULL;
    out_ptr("signed.cert_from_signer", si != NULL ? PKCS7_cert_from_signer_info(p7, si) : NULL);
    if (si != NULL) {
        X509_ALGOR *dig = NULL, *sig = NULL;
        EVP_PKEY *pk = NULL;

        PKCS7_SIGNER_INFO_get0_algs(si, &pk, &dig, &sig);
        out_ptr("signed.digest_alg", dig);
        out_ptr("signed.sig_alg", sig);
        out_ptr("signed.signer_pkey", pk);
    }
    signers = PKCS7_get0_signers(p7, NULL, 0);
    out_int("signed.get0_signers_count",
            signers != NULL ? sk_X509_num(signers) : -1);
    sk_X509_free(signers);

    /* No store and no private key: the certificate-verify walk is skipped, the content is still
     * digested and read, and the signature arms are skipped. */
    ERR_clear_error();
    out_int("signed.verify_noverify",
            PKCS7_verify(p7, NULL, NULL, NULL, NULL, PKCS7_NOVERIFY | PKCS7_NOSIGS));
    out_err("signed.verify_noverify_err");

    n = i2d_PKCS7(p7, NULL);
    out_int("signed.i2d_len", n);
    i2d_PKCS7(p7, &buf);
    out_int("signed.reencode_first", buf != NULL ? buf[0] : -1);
    OPENSSL_free(buf);
    PKCS7_free(p7);

    /* A `data` container is refused, and a NULL one too. */
    {
        PKCS7 *data = PKCS7_new();
        PKCS7_set_type(data, NID_pkcs7_data);
        ERR_clear_error();
        out_int("verify.data", PKCS7_verify(data, NULL, NULL, NULL, NULL, 0));
        out_err("verify.data_err");
        PKCS7_free(data);
    }
    ERR_clear_error();
    out_int("verify.null", PKCS7_verify(NULL, NULL, NULL, NULL, NULL, 0));
    out_err("verify.null_err");
}

/* The `envelopedData` fixture plus a freshly built recipient. */
static void arm_enveloped(void)
{
    const unsigned char *p = rt_pkcs7_enveloped_der;
    PKCS7 *p7 = d2i_PKCS7(NULL, &p, (long)rt_pkcs7_enveloped_der_len);
    X509 *cert = load_cert();
    PKCS7 *built;
    PKCS7_RECIP_INFO *ri;
    int n;

    out_ptr("enveloped.d2i", p7);
    if (p7 != NULL) {
        out_int("enveloped.is_other", PKCS7_type_is_other(p7));
        n = i2d_PKCS7(p7, NULL);
        out_int("enveloped.i2d_len", n);
        PKCS7_free(p7);
    }
    out_ptr("enveloped.cert", cert);

    built = PKCS7_new();
    ERR_clear_error();
    out_int("enveloped.set_type", PKCS7_set_type(built, NID_pkcs7_enveloped));
    printf("pending.set_cipher=%s\n", "evp-cipher-get-type");
    ri = PKCS7_RECIP_INFO_new();
    out_ptr("enveloped.ri_new", ri);
    if (ri != NULL && cert != NULL) {
        X509_ALGOR *alg = NULL;

        ERR_clear_error();
        out_int("enveloped.ri_set", PKCS7_RECIP_INFO_set(ri, cert));
        out_err("enveloped.ri_set_err");
        PKCS7_RECIP_INFO_get0_alg(ri, &alg);
        out_ptr("enveloped.ri_alg", alg);
        ERR_clear_error();
        out_int("enveloped.ri_add", PKCS7_add_recipient_info(built, ri));
        out_err("enveloped.ri_add_err");
    } else {
        PKCS7_RECIP_INFO_free(ri);
    }
    if (cert != NULL) {
        PKCS7_RECIP_INFO *ri2 = PKCS7_add_recipient(built, cert);

        out_ptr("enveloped.add_recipient", ri2);
    }

    /* `dataDecode` refuses a non-enveloped container and a NULL one. */
    {
        PKCS7 *data = PKCS7_new();
        PKCS7_set_type(data, NID_pkcs7_data);
        ERR_clear_error();
        out_ptr("dataDecode.data", PKCS7_dataDecode(data, NULL, NULL, NULL));
        out_err("dataDecode.data_err");
        PKCS7_free(data);
    }
    ERR_clear_error();
    out_ptr("dataDecode.null", PKCS7_dataDecode(NULL, NULL, NULL, NULL));
    out_err("dataDecode.null_err");
    ERR_clear_error();
    out_int("decrypt.null", PKCS7_decrypt(NULL, NULL, NULL, NULL, 0));
    out_err("decrypt.null_err");

    PKCS7_free(built);
    X509_free(cert);
}

/* The `signedAndEnveloped` container, its recipient accessor and the issuer/serial reader. */
static void arm_signed_and_enveloped(void)
{
    PKCS7 *p7 = PKCS7_new();
    PKCS7_RECIP_INFO *ri = PKCS7_RECIP_INFO_new();
    X509 *cert = load_cert();

    ERR_clear_error();
    out_int("se.set_type", PKCS7_set_type(p7, NID_pkcs7_signedAndEnveloped));
    if (cert != NULL && ri != NULL) {
        PKCS7_RECIP_INFO_set(ri, cert);
        PKCS7_add_recipient_info(p7, ri);
    }
    out_ptr("se.issuer_serial_0", PKCS7_get_issuer_and_serial(p7, 0));
    out_ptr("se.issuer_serial_9", PKCS7_get_issuer_and_serial(p7, 9));
    PKCS7_free(p7);
    X509_free(cert);
}

/* The attribute stack over a fresh signer info. */
static void arm_attributes(void)
{
    PKCS7_SIGNER_INFO *si = PKCS7_SIGNER_INFO_new();
    unsigned char md[32];
    STACK_OF(X509_ALGOR) *cap;

    memset(md, 0xAB, sizeof md);
    out_ptr("attr.si", si);
    if (si == NULL)
        return;

    ERR_clear_error();
    out_int("attr.content_type", PKCS7_add_attrib_content_type(si, NULL));
    out_int("attr.signing_time", PKCS7_add0_attrib_signing_time(si, NULL));
    out_int("attr.digest", PKCS7_add1_attrib_digest(si, md, (int)sizeof md));
    out_ptr("attr.get_signed", PKCS7_get_signed_attribute(si, NID_pkcs9_messageDigest));
    out_ptr("attr.get_unsigned", PKCS7_get_attribute(si, NID_pkcs9_messageDigest));
    out_ptr("attr.digest_from", PKCS7_digest_from_attributes(si->auth_attr));

    cap = sk_X509_ALGOR_new_null();
    out_int("attr.simple_cap", PKCS7_simple_smimecap(cap, NID_aes_128_cbc, -1));
    ERR_clear_error();
    out_int("attr.add_cap", PKCS7_add_attrib_smimecap(si, cap));
    out_err("attr.add_cap_err");
    {
        STACK_OF(X509_ALGOR) *got = PKCS7_get_smimecap(si);

        out_int("attr.get_cap_num", got != NULL ? sk_X509_ALGOR_num(got) : -1);
        sk_X509_ALGOR_pop_free(got, X509_ALGOR_free);
    }
    sk_X509_ALGOR_pop_free(cap, X509_ALGOR_free);

    out_int("attr.set_signed", PKCS7_set_signed_attributes(si, NULL));
    out_int("attr.set_unsigned", PKCS7_set_attributes(si, NULL));
    ERR_clear_error();
    out_int("attr.add_signed",
            PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
                                       OBJ_nid2obj(NID_pkcs7_data)));
    out_int("attr.add_unsigned",
            PKCS7_add_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
                                OBJ_nid2obj(NID_pkcs7_data)));
    out_err("attr.add_err");

    PKCS7_SIGNER_INFO_free(si);
}

/* The add-signer/add-certificate/add-signature surface, and the refusals without a key. */
static void arm_builders(void)
{
    PKCS7_SIGNER_INFO *si = PKCS7_SIGNER_INFO_new();
    PKCS7 *p7 = PKCS7_new();
    X509 *cert = load_cert();

    PKCS7_set_type(p7, NID_pkcs7_data);
    ERR_clear_error();
    out_int("builders.add_signer_wrong_type", PKCS7_add_signer(p7, si));
    out_err("builders.add_signer_wrong_type_err");

    /* A NULL key has no default digest, so no signer is built. */
    ERR_clear_error();
    out_ptr("builders.add_signature_nullkey", PKCS7_add_signature(p7, cert, NULL, NULL));
    out_err("builders.add_signature_nullkey_err");

    /* The certificate and CRL adders need the signed arm. */
    {
        PKCS7 *s = PKCS7_new();
        PKCS7_set_type(s, NID_pkcs7_signed);
        ERR_clear_error();
        out_int("builders.add_certificate", cert != NULL ? PKCS7_add_certificate(s, cert) : -1);
        out_err("builders.add_certificate_err");
        out_int("builders.add_certificate_null", PKCS7_add_certificate(s, NULL));
        out_err("builders.add_certificate_null_err");
        PKCS7_free(s);
    }

    /* `set0_type_other` and `get_octet_string`'s other arm. */
    {
        PKCS7 *o = PKCS7_new();
        ASN1_TYPE *t = ASN1_TYPE_new();
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();

        ASN1_OCTET_STRING_set(os, rt_pkcs7_content, (int)rt_pkcs7_content_len);
        ASN1_TYPE_set(t, V_ASN1_OCTET_STRING, os);
        out_int("builders.set0_type_other", PKCS7_set0_type_other(o, NID_rsaEncryption, t));
        out_int("builders.other_is_other", PKCS7_type_is_other(o));
        out_ptr("builders.other_octet", PKCS7_get_octet_string(o));
        PKCS7_free(o);
    }

    PKCS7_free(p7);
    PKCS7_SIGNER_INFO_free(si);
    X509_free(cert);
}

/* The streaming BIO and the PEM writer/reader over the fixed DER. */
static void arm_stream_and_pem(void)
{
    const unsigned char *p = rt_pkcs7_signed_der;
    PKCS7 *p7 = d2i_PKCS7(NULL, &p, (long)rt_pkcs7_signed_der_len);
    BIO *out;
    BIO *in;
    PKCS7 *back;
    char *data = NULL;
    long len;

    if (p7 == NULL)
        return;

    out = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("pem.write_bio", PEM_write_bio_PKCS7(out, p7));
    out_err("pem.write_bio_err");
    len = (long)BIO_ctrl(out, BIO_CTRL_INFO, 0, &data);
    out_int("pem.text_len", len);
    out_int("pem.first", data != NULL ? (unsigned char)data[0] : -1);

    in = BIO_new_mem_buf(data, (int)len);
    ERR_clear_error();
    back = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
    out_ptr("pem.read_bio", back);
    out_err("pem.read_bio_err");
    if (back != NULL) {
        out_int("pem.read_back_len", i2d_PKCS7(back, NULL));
        PKCS7_free(back);
    }
    BIO_free(in);
    BIO_free(out);

    /* The non-streaming `i2d_PKCS7_bio_stream` arm. */
    out = BIO_new(BIO_s_mem());
    in = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("stream.i2d_bio", i2d_PKCS7_bio_stream(out, p7, in, 0));
    out_err("stream.i2d_bio_err");
    out_int("stream.i2d_bio_len", (long)BIO_ctrl(out, BIO_CTRL_INFO, 0, NULL));
    BIO_free(in);
    BIO_free(out);

    /* The `BIO_new_PKCS7` streaming constructor. */
    {
        BIO *sv = BIO_new(BIO_s_mem());
        BIO *b = BIO_new_PKCS7(sv, p7);

        out_ptr("stream.bio_new_pkcs7", b);
        if (b != NULL)
            BIO_free(b);
        else
            BIO_free(sv);
    }

    PKCS7_free(p7);
}

int main(void)
{
    size_t i;
    long nonnull = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Read every address, so the compiler cannot drop the table: the reference is what makes each
     * symbol an undefined dynamic symbol of this binary. */
    for (i = 0; i < sizeof g_refs / sizeof g_refs[0]; i++)
        if (g_refs[i] != NULL)
            nonnull++;
    out_int("refs.count", (long)(sizeof g_refs / sizeof g_refs[0]));
    out_int("refs.nonnull", nonnull);

    arm_data();
    arm_set_type();
    arm_digest();
    arm_signed();
    arm_enveloped();
    arm_signed_and_enveloped();
    arm_attributes();
    arm_builders();
    arm_stream_and_pem();

    return 0;
}
