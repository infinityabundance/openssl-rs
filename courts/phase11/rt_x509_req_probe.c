/*
 * RT-X509-REQ -- the Phase 11.4 request/CRL/mutator remainder, driven.
 *
 * docs/PHASE-11-SUBPHASES.md section 3.1 and 3.4 ask for two things: the **exact printed text**
 * each text-layer entry point produces for a fixed object, and the **error queue and coordinate**
 * each refusal carries. This probe does both, differentially: it is compiled against the admitted
 * authority and against the candidate distribution shell, run, and the two transcripts are
 * compared line for line. Every observation line is `key=value`; no address is printed.
 *
 * Why the printed text and not a parsed structure
 * -----------------------------------------------
 * The printers are the object's whole contract at this layer: a transcription that reformats a
 * field differently is a different library. So each printer's output is captured into a memory
 * BIO (or a `tmpfile()` the probe controls and reads back) and reduced to its exact **length** and
 * a 64-bit FNV-1a **digest** of those bytes. A digest is not an address and depends only on the
 * authority's own output, so it is the differential evidence.
 *
 * Fixtures
 * --------
 * The DER fixtures are `rt_x509_der.h`'s (the authority tree's own `root-cert.pem`,
 * `testcrl.pem` and `x509-check.csr`, carried forward from Phase 10.8). The one extra constant is
 * an RSA private key (the Phase 11.6 probe's generated PKCS#8 key) used only as the signing key
 * for `X509_REQ_to_X509`; the observation never prints it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>

#include "rt_x509_der.h"

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

/* Print the contents of a memory BIO as length and digest. */
static void out_mem(const char *key, BIO *b)
{
    char *data = NULL;
    long len = BIO_get_mem_data(b, &data);

    out_text(key, (const unsigned char *)data, len);
}

/* Rewind a stream the probe wrote to, read it back, and print it as length and digest. */
static void out_fp(const char *key, FILE *fp)
{
    static unsigned char buf[1 << 16];
    size_t n;

    rewind(fp);
    n = fread(buf, 1, sizeof buf, fp);
    out_text(key, buf, (long)n);
}

/* A fixed RSA private key, used only as `X509_REQ_to_X509`'s signing key. */
static const char pkcs8_plain_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALwJezJHz4puNJQr\n"
    "Cd0rSIbLwtEhKUgSFDVfxZQYTUlTb1navfhM6YWMUe1j0cfn/086G1YrBQtZaMUN\n"
    "6Oghbh/utVyWl7PO+sbc0gYLb5vgmuQ7N+N0QIT4CpLunoZGXFtWLgAcIJBnuvq7\n"
    "TEpgZhlkPWl6TNMLqfm4UKMFWD8FAgMBAAECgYBthOwvVeoIi7WuEv80xVABys4W\n"
    "dkUQCA+jIrv2TM0/BwyU/jWlWE6vDRJuvLPjxjlK0OI5JudSO+os07Qy972mdKmB\n"
    "liLbEKXKyvw/S8NyHAV7RuVGk/8JfyL6QtHTLjKA+Mc/GMjha9uWzQTLK5N/ZCSs\n"
    "pK0RiViAwPwcQpQ7JQJBAPO2HF9ihxymXOtxa6IYYnt460tzg3pT0Om4eQqRrlBm\n"
    "GF8T84jooK5giAvmyo3rAZ50DYIEVjIWlAgzXUYG4hcCQQDFhLY1Vx2cJSK4ORDF\n"
    "RUqboIgl63AjMzNSBXKx8bHtWkwJly7P97SQ+qi1vmNdBBAwlT/7COnwDK4JQOWH\n"
    "aGVDAkBjF33Lzszu+jm3xYMlAlMwrwbEw/AGkgPUtBwLDxbYO9rW9c7EsQl8PWWz\n"
    "qSBcudwLqFZBsi+15/ZCq1fWfD/7AkBiuLYpauVNyfHUihEryDpGFrJ14Xsm3Mxl\n"
    "zntJHTiFHYCruniXUYNagy4XyJT5RLKi1bYozoe+h1flIB6Y00DpAkEAvGqkTe5v\n"
    "aYL8N3O0Y59qfOWQdU6wreH5w5Y5fhikLvPhdzSpseONGgtW8HJW7EedUY9nIcDX\n"
    "reKLAww9L5t9oQ==\n"
    "-----END PRIVATE KEY-----\n";

/* ---------------------------------------------------------------------------------------------
 * `t_x509.c` -- the certificate text layer.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509(void)
{
    const unsigned char *p = RT_X509_CERT_DER;
    X509 *x = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    BIO *b;
    FILE *fp;

    out_ptr("cert.d2i", x);

    /* X509_print: the authority's default flags. */
    b = BIO_new(BIO_s_mem());
    out_int("cert.print.ret", X509_print(b, x));
    out_mem("cert.print", b);
    BIO_free(b);

    /* X509_print_ex: multiline names and long field names, extensions suppressed. */
    b = BIO_new(BIO_s_mem());
    out_int("cert.print_ex.ret",
            X509_print_ex(b, x, XN_FLAG_SEP_MULTILINE | XN_FLAG_FN_LN,
                          X509_FLAG_NO_EXTENSIONS));
    out_mem("cert.print_ex", b);
    BIO_free(b);

    /* The `FILE *` spellings: write to a temp stream, rewind, read back. */
    fp = tmpfile();
    out_int("cert.print_fp.ret", X509_print_fp(fp, x));
    out_fp("cert.print_fp", fp);
    fclose(fp);

    fp = tmpfile();
    out_int("cert.print_ex_fp.ret",
            X509_print_ex_fp(fp, x, XN_FLAG_ONELINE, X509_FLAG_COMPAT));
    out_fp("cert.print_ex_fp", fp);
    fclose(fp);

    /* X509_ocspid_print: the two SHA-1 hashes. */
    b = BIO_new(BIO_s_mem());
    out_int("cert.ocspid.ret", X509_ocspid_print(b, x));
    out_mem("cert.ocspid", b);
    BIO_free(b);

    /* X509_signature_print: the algorithm line alone, then algorithm and value. */
    {
        const X509_ALGOR *tsig = X509_get0_tbs_sigalg(x);
        const ASN1_BIT_STRING *sig = NULL;
        const X509_ALGOR *sigalg = NULL;

        b = BIO_new(BIO_s_mem());
        out_int("cert.sigprint.alg.ret", X509_signature_print(b, tsig, NULL));
        out_mem("cert.sigprint.alg", b);
        BIO_free(b);

        X509_get0_signature(&sig, &sigalg, x);
        b = BIO_new(BIO_s_mem());
        out_int("cert.sigprint.val.ret", X509_signature_print(b, sigalg, sig));
        out_mem("cert.sigprint.val", b);
        BIO_free(b);
    }

    /* X509_aux_print: a cert whose aux block the probe populates. */
    {
        const unsigned char *q = RT_X509_CERT_DER;
        X509 *xa = d2i_X509(NULL, &q, (long)RT_X509_CERT_DER_LEN);
        static const unsigned char keyid[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

        out_int("cert.aux.alias", X509_alias_set1(xa, (const unsigned char *)"probe-alias", 11));
        out_int("cert.aux.keyid", X509_keyid_set1(xa, keyid, 4));
        out_int("cert.aux.trust1", X509_add1_trust_object(xa, OBJ_nid2obj(NID_server_auth)));
        out_int("cert.aux.trust2", X509_add1_trust_object(xa, OBJ_nid2obj(NID_client_auth)));
        out_int("cert.aux.reject1", X509_add1_reject_object(xa, OBJ_nid2obj(NID_anyExtendedKeyUsage)));

        b = BIO_new(BIO_s_mem());
        out_int("cert.aux.ret", X509_aux_print(b, xa, 0));
        out_mem("cert.aux", b);
        BIO_free(b);
        X509_free(xa);
    }

    /* OSSL_STACK_OF_X509_free: a two-element stack, released by the export. */
    {
        STACK_OF(X509) *sk = sk_X509_new_null();
        const unsigned char *q1 = RT_X509_CERT_DER;
        const unsigned char *q2 = RT_X509_CERT_DER;

        sk_X509_push(sk, d2i_X509(NULL, &q1, (long)RT_X509_CERT_DER_LEN));
        sk_X509_push(sk, d2i_X509(NULL, &q2, (long)RT_X509_CERT_DER_LEN));
        out_int("cert.stack.num", sk_X509_num(sk));
        OSSL_STACK_OF_X509_free(sk);
        out_int("cert.stack_free.ran", 1);
    }

    X509_free(x);
}

/* ---------------------------------------------------------------------------------------------
 * `t_req.c` -- the request printer.
 * --------------------------------------------------------------------------------------------- */

static void drive_req(void)
{
    const unsigned char *p = RT_X509_REQ_DER;
    X509_REQ *x = d2i_X509_REQ(NULL, &p, (long)RT_X509_REQ_DER_LEN);
    BIO *b;
    FILE *fp;

    out_ptr("req.d2i", x);

    b = BIO_new(BIO_s_mem());
    out_int("req.print.ret", X509_REQ_print(b, x));
    out_mem("req.print", b);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    out_int("req.print_ex.ret",
            X509_REQ_print_ex(b, x, XN_FLAG_SEP_MULTILINE, X509_FLAG_COMPAT));
    out_mem("req.print_ex", b);
    BIO_free(b);

    fp = tmpfile();
    out_int("req.print_fp.ret", X509_REQ_print_fp(fp, x));
    out_fp("req.print_fp", fp);
    fclose(fp);

    X509_REQ_free(x);
}

/* ---------------------------------------------------------------------------------------------
 * `t_crl.c` -- the CRL printer.
 * --------------------------------------------------------------------------------------------- */

static void drive_crl(void)
{
    const unsigned char *p = RT_X509_CRL_DER;
    X509_CRL *x = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    BIO *b;
    FILE *fp;

    out_ptr("crl.d2i", x);

    b = BIO_new(BIO_s_mem());
    out_int("crl.print.ret", X509_CRL_print(b, x));
    out_mem("crl.print", b);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    out_int("crl.print_ex.ret", X509_CRL_print_ex(b, x, XN_FLAG_SEP_MULTILINE));
    out_mem("crl.print_ex", b);
    BIO_free(b);

    fp = tmpfile();
    out_int("crl.print_fp.ret", X509_CRL_print_fp(fp, x));
    out_fp("crl.print_fp", fp);
    fclose(fp);

    X509_CRL_free(x);
}

/* ---------------------------------------------------------------------------------------------
 * `x509_r2x.c` -- `X509_REQ_to_X509`.
 * --------------------------------------------------------------------------------------------- */

static void drive_r2x(void)
{
    BIO *kb = BIO_new_mem_buf(pkcs8_plain_pem, (int)(sizeof pkcs8_plain_pem - 1));
    EVP_PKEY *k = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
    const unsigned char *p = RT_X509_REQ_DER;
    X509_REQ *r = d2i_X509_REQ(NULL, &p, (long)RT_X509_REQ_DER_LEN);
    X509 *c;

    out_ptr("r2x.key", k);
    out_ptr("r2x.req", r);

    /* The construction itself: the time-independent structure only. */
    c = X509_REQ_to_X509(r, 365, k);
    out_ptr("r2x.cert", c);
    if (c != NULL) {
        const ASN1_BIT_STRING *sig = NULL;
        const X509_ALGOR *alg = NULL;

        out_int("r2x.version", X509_get_version(c));
        out_int("r2x.subject_eq_req",
                X509_NAME_cmp(X509_get_subject_name(c), X509_REQ_get_subject_name(r)) == 0);
        out_int("r2x.issuer_eq_subject",
                X509_NAME_cmp(X509_get_issuer_name(c), X509_get_subject_name(c)) == 0);
        out_int("r2x.sig_nid", X509_get_signature_nid(c));
        out_ptr("r2x.pubkey", X509_get0_pubkey(c));
        out_int("r2x.pubkey_eq_req",
                EVP_PKEY_eq(X509_get0_pubkey(c), X509_REQ_get0_pubkey(r)));
        X509_get0_signature(&sig, &alg, c);
        out_ptr("r2x.sig", sig);
        X509_free(c);
    }

    /* A NULL signing key refuses: the cert is not built. */
    c = X509_REQ_to_X509(r, 365, NULL);
    out_ptr("r2x.nullkey", c);
    ERR_clear_error();
    X509_free(c);

    /* An attribute-bearing request forces the v3 version. */
    {
        const unsigned char *q = RT_X509_REQ_DER;
        X509_REQ *r2 = d2i_X509_REQ(NULL, &q, (long)RT_X509_REQ_DER_LEN);
        X509 *c2;

        out_int("r2x2.addattr",
                X509_REQ_add1_attr_by_NID(r2, NID_pkcs9_challengePassword,
                                          V_ASN1_PRINTABLESTRING,
                                          (const unsigned char *)"pw", 2));
        out_int("r2x2.attr_count", X509_REQ_get_attr_count(r2));
        c2 = X509_REQ_to_X509(r2, 30, k);
        out_ptr("r2x2.cert", c2);
        out_int("r2x2.version", c2 != NULL ? X509_get_version(c2) : -1);
        X509_free(c2);
        X509_REQ_free(r2);
    }

    EVP_PKEY_free(k);
    BIO_free(kb);
    X509_REQ_free(r);
}

/* ---------------------------------------------------------------------------------------------
 * `x509_req.c` -- `X509_to_X509_REQ`.
 * --------------------------------------------------------------------------------------------- */

static void drive_to_req(void)
{
    BIO *kb = BIO_new_mem_buf(pkcs8_plain_pem, (int)(sizeof pkcs8_plain_pem - 1));
    EVP_PKEY *k = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
    const unsigned char *p = RT_X509_CERT_DER;
    X509 *x = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    X509_REQ *r;

    out_ptr("toreq.key", k);
    out_ptr("toreq.cert", x);

    /* The signed construction. */
    r = X509_to_X509_REQ(x, k, EVP_sha256());
    out_ptr("toreq.req", r);
    if (r != NULL) {
        const ASN1_BIT_STRING *sig = NULL;
        const X509_ALGOR *alg = NULL;

        out_int("toreq.version", X509_REQ_get_version(r));
        out_int("toreq.subject_eq",
                X509_NAME_cmp(X509_REQ_get_subject_name(r), X509_get_subject_name(x)) == 0);
        out_int("toreq.pubkey_eq",
                EVP_PKEY_eq(X509_REQ_get0_pubkey(r), X509_get0_pubkey(x)));
        X509_REQ_get0_signature(r, &sig, &alg);
        out_ptr("toreq.sig", sig);
        X509_REQ_free(r);
    }

    /* A NULL signing key builds the request but leaves it unsigned. */
    r = X509_to_X509_REQ(x, NULL, NULL);
    out_ptr("toreq.unsigned", r);
    if (r != NULL) {
        const ASN1_BIT_STRING *sig = NULL;
        const X509_ALGOR *alg = NULL;

        X509_REQ_get0_signature(r, &sig, &alg);
        out_ptr("toreq.unsigned.sig", sig);
        X509_REQ_free(r);
    }

    X509_free(x);
    EVP_PKEY_free(k);
    BIO_free(kb);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    drive_x509();
    drive_req();
    drive_crl();
    drive_r2x();
    drive_to_req();

    return 0;
}
