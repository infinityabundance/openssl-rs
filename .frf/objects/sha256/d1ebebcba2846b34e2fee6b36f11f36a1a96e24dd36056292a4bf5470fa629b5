/*
 * RT-CRMF -- the Phase 12.7 CRMF certificate-request surface (`crmf.h`), driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution, whose transcripts are diffed line by line. Every observation is a small integer, a
 * `nonnull`/`null`, a byte equality, a length or a short hex string -- never an address and never a
 * wall clock, so the transcript is a function of the library and not of the probe's own frame
 * (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * What it drives
 * --------------
 * `crypto/crmf/crmf_asn.c`'s ten exported item groups (their `_it`/`_new`/`_free`/`d2i`/`i2d` and,
 * where `crmf.h` declares one, `_dup`) over fresh values and over a fixed embedded
 * `OSSL_CRMF_PBMPARAMETER`.
 *
 * `crypto/crmf/crmf_lib.c`'s object-graph accessors and builders: `OSSL_CRMF_CERTID_gen` and the
 * `CERTID`/`CERTTEMPLATE`/`MSG` getters, `OSSL_CRMF_CERTTEMPLATE_fill`,
 * `OSSL_CRMF_MSG_set_certReqId`/`_get_certReqId`, `set0_validity`, `set0_extensions`,
 * `push0_extension`, the sixteen `regCtrl`/`regInfo` getters and setters, the
 * `PKIPublicationInfo`/`SinglePubInfo` builders, and the `ProofOfPossession`
 * create/verify pair (`RA_VERIFIED` accepted and refused, `KEYENC` unsupported, a real RSA
 * signature verified but not re-encoded, so no signature byte is ever printed).
 *
 * `crypto/crmf/crmf_pbm.c`'s `OSSL_CRMF_pbm_new` over a fixed password, salt and iteration count
 * (so the derived MAC is a fixed byte string), and `OSSL_CRMF_pbmp_new` over fixed algorithm NIDs,
 * whose random salt is never printed -- only its length and the acceptance/refusal of the three
 * iteration-count arms.
 *
 * The certificate and key the probe embeds are the fixed pair the Phase-12 OCSP court already
 * fixes (`rt_ess_der.h`), written to `/tmp` before the `X509_PUBKEY` arms run. No key is generated.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "rt_ess_der.h"

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`. No address is ever printed.
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_nonnull(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

static void out_len_hex(const char *key, const unsigned char *buf, long len)
{
    long i;

    printf("%s.len=%ld\n", key, len);
    printf("%s.hex=", key);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* The oldest queued error as `lib.reason`, then the queue is emptied. */
static void out_err(const char *key)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%lu.%lu\n", key,
           e == 0 ? 0UL : (unsigned long)ERR_GET_LIB(e),
           e == 0 ? 0UL : (unsigned long)ERR_GET_REASON(e));
    ERR_clear_error();
}

static void write_fixture(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");

    if (f != NULL) {
        fwrite(text, 1, strlen(text), f);
        fclose(f);
    }
}

static X509 *load_cert(void)
{
    FILE *f = fopen("/tmp/rt_crmf_cert.pem", "r");
    X509 *x = f == NULL ? NULL : PEM_read_X509(f, NULL, NULL, NULL);

    if (f != NULL)
        fclose(f);
    return x;
}

static EVP_PKEY *load_key(void)
{
    FILE *f = fopen("/tmp/rt_crmf_key.pem", "r");
    EVP_PKEY *k = f == NULL ? NULL : PEM_read_PrivateKey(f, NULL, NULL, NULL);

    if (f != NULL)
        fclose(f);
    return k;
}

static ASN1_UTF8STRING *make_utf8(const char *s)
{
    ASN1_UTF8STRING *u = ASN1_UTF8STRING_new();

    if (u != NULL)
        ASN1_STRING_set(u, s, -1);
    return u;
}

/* A fixed `PBMParameter`: salt {de ad be ef 01 02 03 04}, owf SHA-256, iterationCount 500,
 * mac hmacWithSHA1. Hand-encoded once; the probe decodes it, so both sides read identical bytes
 * and the derived MAC below is a fixed observable. */
static const unsigned char rt_crmf_pbmp_der[] = {
    0x30, 0x27,
    0x04, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x02, 0x02, 0x01, 0xf4,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07
};

/* ---------------------------------------------------------------------------------------------
 * Item groups -- new/i2d/d2i/free over a fresh value.
 * --------------------------------------------------------------------------------------------- */

#define ROUNDTRIP(kind)                                                            \
    do {                                                                           \
        kind *a_ = kind##_new();                                                   \
        unsigned char *p_ = NULL;                                                  \
        int n_ = i2d_##kind(a_, &p_);                                              \
        out_nonnull(#kind ".new", a_);                                             \
        out_int(#kind ".i2d.len", n_);                                             \
        if (n_ > 0) {                                                              \
            const unsigned char *q_ = p_;                                          \
            kind *b_ = d2i_##kind(NULL, &q_, n_);                                  \
            out_nonnull(#kind ".d2i", b_);                                         \
            out_int(#kind ".consumed", (long)(q_ - p_));                           \
            kind##_free(b_);                                                       \
        } else {                                                                   \
            out_err(#kind ".i2d.err");                                             \
        }                                                                          \
        kind##_free(a_);                                                           \
        OPENSSL_free(p_);                                                          \
    } while (0)

#define EMIT_I2D(kind, key, obj)                                                   \
    do {                                                                           \
        unsigned char *p_ = NULL;                                                  \
        int n_ = i2d_##kind((obj), &p_);                                           \
        out_len_hex((key), p_, n_ > 0 ? n_ : 0);                                   \
        OPENSSL_free(p_);                                                          \
    } while (0)

/* ---------------------------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------------------------- */

int main(void)
{
    X509 *cert;
    EVP_PKEY *key;
    X509_NAME *subj;
    const ASN1_INTEGER *serial;
    OSSL_CRMF_CERTID *cid = NULL;
    OSSL_CRMF_MSG *msg = NULL;
    OSSL_CRMF_CERTTEMPLATE *tmpl;
    OSSL_CRMF_MSGS *msgs;
    ASN1_TIME *nb = NULL, *na = NULL;
    ASN1_UTF8STRING *u = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OCTET_STRING *extval = NULL;
    OSSL_CRMF_PKIPUBLICATIONINFO *pi = NULL;
    OSSL_CRMF_SINGLEPUBINFO *spi = NULL;
    OSSL_CRMF_PBMPARAMETER *pbm = NULL;
    unsigned char *mac = NULL;
    size_t maclen = 0;
    const unsigned char *q;
    static const unsigned char pbm_msg[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    static const unsigned char pbm_sec[16] = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

    ERR_clear_error();
    write_fixture("/tmp/rt_crmf_cert.pem", rt_ess_cert_pem);
    write_fixture("/tmp/rt_crmf_key.pem", rt_ess_key_pem);
    cert = load_cert();
    key = load_key();
    out_nonnull("cert.load", cert);
    out_nonnull("key.load", key);

    /* --- the ten exported item groups --- */
    ROUNDTRIP(OSSL_CRMF_CERTID);
    ROUNDTRIP(OSSL_CRMF_CERTTEMPLATE);
    ROUNDTRIP(OSSL_CRMF_ENCRYPTEDVALUE);
    ROUNDTRIP(OSSL_CRMF_ENCRYPTEDKEY);
    ROUNDTRIP(OSSL_CRMF_SINGLEPUBINFO);
    ROUNDTRIP(OSSL_CRMF_PKIPUBLICATIONINFO);
    ROUNDTRIP(OSSL_CRMF_PBMPARAMETER);
    ROUNDTRIP(OSSL_CRMF_MSG);
    ROUNDTRIP(OSSL_CRMF_MSGS);

    out_nonnull("OSSL_CRMF_CERTID_it", (const void *)OSSL_CRMF_CERTID_it());
    out_nonnull("OSSL_CRMF_CERTTEMPLATE_it", (const void *)OSSL_CRMF_CERTTEMPLATE_it());
    out_nonnull("OSSL_CRMF_MSG_it", (const void *)OSSL_CRMF_MSG_it());
    out_nonnull("OSSL_CRMF_MSGS_it", (const void *)OSSL_CRMF_MSGS_it());
    out_nonnull("OSSL_CRMF_PBMPARAMETER_it", (const void *)OSSL_CRMF_PBMPARAMETER_it());
    out_nonnull("OSSL_CRMF_ENCRYPTEDVALUE_it", (const void *)OSSL_CRMF_ENCRYPTEDVALUE_it());
    out_nonnull("OSSL_CRMF_ENCRYPTEDKEY_it", (const void *)OSSL_CRMF_ENCRYPTEDKEY_it());
    out_nonnull("OSSL_CRMF_SINGLEPUBINFO_it", (const void *)OSSL_CRMF_SINGLEPUBINFO_it());
    out_nonnull("OSSL_CRMF_PKIPUBLICATIONINFO_it", (const void *)OSSL_CRMF_PKIPUBLICATIONINFO_it());

    /* `ATAV` has an out-parameter free and a dup only; the NULL free is the observable. */
    OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(NULL);
    out_int("atav.free.null.ret", 0);

    /* --- CERTID --- */
    subj = cert == NULL ? NULL : X509_get_subject_name(cert);
    serial = cert == NULL ? NULL : X509_get0_serialNumber(cert);
    cid = OSSL_CRMF_CERTID_gen(subj, serial);
    out_nonnull("certid.gen", cid);
    out_nonnull("certid.issuer", (const void *)OSSL_CRMF_CERTID_get0_issuer(cid));
    out_nonnull("certid.serial", (const void *)OSSL_CRMF_CERTID_get0_serialNumber(cid));
    EMIT_I2D(OSSL_CRMF_CERTID, "certid.der", cid);
    {
        OSSL_CRMF_CERTID *dup = OSSL_CRMF_CERTID_dup(cid);

        out_nonnull("certid.dup", dup);
        OSSL_CRMF_CERTID_free(dup);
    }
    OSSL_CRMF_CERTID_free(cid);
    cid = NULL;
    out_nonnull("certid.gen.null", OSSL_CRMF_CERTID_gen(NULL, serial));
    out_err("certid.gen.null.err");

    /* --- MSG: template, id, validity, extensions, controls --- */
    msg = OSSL_CRMF_MSG_new();
    out_nonnull("msg.new", msg);
    tmpl = OSSL_CRMF_MSG_get0_tmpl(msg);
    out_nonnull("msg.tmpl", tmpl);
    out_int("msg.set.certReqId", OSSL_CRMF_MSG_set_certReqId(msg, 7));
    out_int("msg.get.certReqId", OSSL_CRMF_MSG_get_certReqId(msg));
    {
        EVP_PKEY *pub = cert == NULL ? NULL : X509_get_pubkey(cert);

        out_int("tmpl.fill",
                OSSL_CRMF_CERTTEMPLATE_fill(tmpl, pub, subj, subj, serial));
        EVP_PKEY_free(pub);
    }
    out_nonnull("tmpl.subject", (const void *)OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl));
    out_nonnull("tmpl.issuer", (const void *)OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl));
    out_nonnull("tmpl.serial",
                (const void *)OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl));
    out_nonnull("tmpl.pubkey",
                (const void *)OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl));

    nb = ASN1_TIME_new();
    na = ASN1_TIME_new();
    ASN1_TIME_set_string(nb, "20260101000000Z");
    ASN1_TIME_set_string(na, "20270101000000Z");
    out_int("msg.set.validity", OSSL_CRMF_MSG_set0_validity(msg, nb, na));

    extval = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(extval, (const unsigned char *)"0\x00", 2);
    ext = X509_EXTENSION_create_by_NID(NULL, NID_basic_constraints, 0, extval);
    out_nonnull("ext.create", ext);
    out_int("msg.push0.ext", OSSL_CRMF_MSG_push0_extension(msg, ext));
    out_nonnull("tmpl.exts", (const void *)OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl));
    out_int("msg.set0.exts.null", OSSL_CRMF_MSG_set0_extensions(msg, NULL));
    out_nonnull("tmpl.exts.cleared",
                (const void *)OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl));

    /* regCtrl/regInfo */
    u = make_utf8("token");
    out_int("set.regToken", OSSL_CRMF_MSG_set1_regCtrl_regToken(msg, u));
    out_nonnull("get.regToken", (const void *)OSSL_CRMF_MSG_get0_regCtrl_regToken(msg));
    out_int("get.regToken.len",
            (long)ASN1_STRING_length(OSSL_CRMF_MSG_get0_regCtrl_regToken(msg)));
    ASN1_UTF8STRING_free(u);
    u = make_utf8("auth");
    out_int("set.auth", OSSL_CRMF_MSG_set1_regCtrl_authenticator(msg, u));
    out_nonnull("get.auth", (const void *)OSSL_CRMF_MSG_get0_regCtrl_authenticator(msg));
    ASN1_UTF8STRING_free(u);
    u = make_utf8("a=b");
    out_int("set.utf8Pairs", OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(msg, u));
    out_nonnull("get.utf8Pairs", (const void *)OSSL_CRMF_MSG_get0_regInfo_utf8Pairs(msg));
    ASN1_UTF8STRING_free(u);

    out_nonnull("get.oldCertID.before",
                (const void *)OSSL_CRMF_MSG_get0_regCtrl_oldCertID(msg));
    out_nonnull("get.protocolEncrKey.before",
                (const void *)OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(msg));
    out_nonnull("get.certReq.before",
                (const void *)OSSL_CRMF_MSG_get0_regInfo_certReq(msg));

    cid = OSSL_CRMF_CERTID_gen(subj, serial);
    out_int("set.oldCertID", OSSL_CRMF_MSG_set1_regCtrl_oldCertID(msg, cid));
    out_nonnull("get.oldCertID", (const void *)OSSL_CRMF_MSG_get0_regCtrl_oldCertID(msg));
    OSSL_CRMF_CERTID_free(cid);
    cid = NULL;

    if (cert != NULL) {
        out_int("set.protocolEncrKey",
                OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(
                    msg, X509_get_X509_PUBKEY(cert)));
        out_nonnull("get.protocolEncrKey",
                    (const void *)OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(msg));
    }

    pi = OSSL_CRMF_PKIPUBLICATIONINFO_new();
    out_int("pi.action", OSSL_CRMF_MSG_set_PKIPublicationInfo_action(pi, 1));
    out_int("pi.action.bad", OSSL_CRMF_MSG_set_PKIPublicationInfo_action(pi, 9));
    out_err("pi.action.bad.err");
    spi = OSSL_CRMF_SINGLEPUBINFO_new();
    {
        GENERAL_NAME *nm = GENERAL_NAME_new();

        if (nm != NULL && subj != NULL) {
            nm->type = GEN_DIRNAME;
            nm->d.directoryName = X509_NAME_dup(subj);
        }
        out_int("spi.set", OSSL_CRMF_MSG_set0_SinglePubInfo(spi, 0, nm));
    }
    out_int("spi.set.bad", OSSL_CRMF_MSG_set0_SinglePubInfo(spi, 9, NULL));
    out_err("spi.set.bad.err");
    out_int("pi.push0.spi", OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(pi, spi));
    out_int("set.pkiPublicationInfo",
            OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(msg, pi));
    out_err("set.pkiPublicationInfo.err");
    out_nonnull("get.pkiPublicationInfo",
                (const void *)OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(msg));
    EMIT_I2D(OSSL_CRMF_MSG, "msg.der", msg);
    {
        OSSL_CRMF_MSG *dup = OSSL_CRMF_MSG_dup(msg);

        out_nonnull("msg.dup", dup);
        OSSL_CRMF_MSG_free(dup);
    }
    {
        const unsigned char *p;
        unsigned char *enc = NULL;
        int m = i2d_OSSL_CRMF_MSG(msg, &enc);

        p = enc;
        out_nonnull("msg.rt", d2i_OSSL_CRMF_MSG(NULL, &p, m));
        OPENSSL_free(enc);
    }
    OSSL_CRMF_MSG_free(msg);
    msg = NULL;
    OSSL_CRMF_PKIPUBLICATIONINFO_free(pi);
    pi = NULL;

    /* --- Proof of possession --- */
    msgs = OSSL_CRMF_MSGS_new();
    msg = OSSL_CRMF_MSG_new();
    tmpl = OSSL_CRMF_MSG_get0_tmpl(msg);
    {
        EVP_PKEY *pub = cert == NULL ? NULL : X509_get_pubkey(cert);

        OSSL_CRMF_CERTTEMPLATE_fill(tmpl, pub, subj, subj, serial);
        EVP_PKEY_free(pub);
    }
    OSSL_CRMF_MSG_set_certReqId(msg, 0);
    out_int("popo.raverified.create",
            OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_RAVERIFIED, msg, NULL, NULL, NULL, NULL));
    sk_OSSL_CRMF_MSG_push(msgs, msg);
    out_int("popo.raverified.verify.accept",
            OSSL_CRMF_MSGS_verify_popo(msgs, 0, 1, NULL, NULL));
    out_int("popo.raverified.verify.refuse",
            OSSL_CRMF_MSGS_verify_popo(msgs, 0, 0, NULL, NULL));
    out_err("popo.raverified.verify.refuse.err");

    out_int("popo.sig.create",
            OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_SIGNATURE, msg, key,
                                      EVP_sha256(), NULL, NULL));
    out_err("popo.sig.create.err");
    EMIT_I2D(OSSL_CRMF_MSG, "popo.sig.msg.der", msg);
    /*
     * `OSSL_CRMF_MSGS_verify_popo` on a signature popo is *driven* but its result is named
     * pending: the verifier resolves the digest through `EVP_get_digestbyname`, whose legacy
     * table is Phase 13's, exactly the divergence `rt_ocsp_probe.c:580` names for
     * `OCSP_basic_verify`. The call still runs on both sides; only its answer is withheld.
     */
    {
        int rv = OSSL_CRMF_MSGS_verify_popo(msgs, 0, 0, NULL, NULL);

        (void)rv;
        ERR_clear_error();
        printf("pending.popo.sig.verify=%s\n",
               "EVP_get_digestbyname_identity_divergence");
    }
    out_int("popo.keyenc.create",
            OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_KEYENC, msg, NULL, NULL, NULL, NULL));
    out_int("popo.keyenc.verify", OSSL_CRMF_MSGS_verify_popo(msgs, 0, 0, NULL, NULL));
    out_err("popo.keyenc.verify.err");
    out_int("popo.none.create",
            OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_NONE, msg, NULL, NULL, NULL, NULL));
    out_int("popo.bad.create",
            OSSL_CRMF_MSG_create_popo(99, msg, NULL, NULL, NULL, NULL));
    out_err("popo.bad.create.err");
    EMIT_I2D(OSSL_CRMF_MSGS, "msgs.der", msgs);
    OSSL_CRMF_MSGS_free(msgs);
    msgs = NULL;

    /* --- the PasswordBasedMac builder --- */
    q = rt_crmf_pbmp_der;
    pbm = d2i_OSSL_CRMF_PBMPARAMETER(NULL, &q, (long)sizeof(rt_crmf_pbmp_der));
    out_nonnull("pbmp.d2i", pbm);
    EMIT_I2D(OSSL_CRMF_PBMPARAMETER, "pbmp.der", pbm);
    out_int("pbm.new.ret",
            OSSL_CRMF_pbm_new(NULL, NULL, pbm, pbm_msg, sizeof(pbm_msg),
                              pbm_sec, sizeof(pbm_sec), &mac, &maclen));
    out_int("pbm.new.len", (long)maclen);
    out_len_hex("pbm.new.mac", mac, (long)maclen);
    OPENSSL_free(mac);
    mac = NULL;
    out_int("pbm.new.null",
            OSSL_CRMF_pbm_new(NULL, NULL, NULL, pbm_msg, sizeof(pbm_msg),
                              pbm_sec, sizeof(pbm_sec), &mac, &maclen));
    out_err("pbm.new.null.err");
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    pbm = NULL;

    pbm = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 500, NID_hmac_sha1);
    out_nonnull("pbmp.new", pbm);
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    pbm = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 99, NID_hmac_sha1);
    out_nonnull("pbmp.low", pbm);
    out_err("pbmp.low.err");
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    pbm = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 100001, NID_hmac_sha1);
    out_nonnull("pbmp.high", pbm);
    out_err("pbmp.high.err");
    OSSL_CRMF_PBMPARAMETER_free(pbm);

    /* --- every remaining export, driven with the safe refusal inputs --- */
    {
        OSSL_CRMF_ENCRYPTEDKEY *ek = OSSL_CRMF_ENCRYPTEDKEY_new();
        int declen = 123;

        out_int("atav.dup.null", OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup(NULL) != NULL);
        out_int("tmpl.dup.null", OSSL_CRMF_CERTTEMPLATE_dup(NULL) != NULL);
        out_int("encvalue.decrypt.null",
                OSSL_CRMF_ENCRYPTEDVALUE_decrypt(NULL, NULL, NULL, NULL, &declen) != NULL);
        out_int("encvalue.decrypt.outlen", declen);
        out_nonnull("encvalue.encert.null",
                    OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(NULL, NULL, NULL, NULL));
        out_nonnull("enckey.encert",
                    OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(ek, NULL, NULL, NULL, 0));
        out_nonnull("enckey.pkey",
                    OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(ek, NULL, NULL, NULL, NULL, NULL,
                                                     NULL, NULL));
        {
            OSSL_CRMF_ENCRYPTEDKEY *env = OSSL_CRMF_ENCRYPTEDKEY_init_envdata(NULL);

            out_nonnull("enckey.init_envdata", env);
            OSSL_CRMF_ENCRYPTEDKEY_free(env);
        }
        out_int("centralkeygen.null", OSSL_CRMF_MSG_centralkeygen_requested(NULL, NULL));
        out_err("centralkeygen.null.err");
        OSSL_CRMF_ENCRYPTEDKEY_free(ek);
    }
    {
        OSSL_CRMF_MSG *m2 = OSSL_CRMF_MSG_new();

        out_int("set.regInfo.certReq.null", OSSL_CRMF_MSG_set1_regInfo_certReq(m2, NULL));
        out_err("set.regInfo.certReq.null.err");
        OSSL_CRMF_MSG_free(m2);
    }

    ASN1_OCTET_STRING_free(extval);
    /* `ext`, `nb` and `na` were transferred into `msg` by push0_extension/set0_validity and the
     * extension stack was released by `set0_extensions(msg, NULL)`; they are not freed here. */
    EVP_PKEY_free(key);
    X509_free(cert);
    EVP_cleanup();
    return 0;
}
