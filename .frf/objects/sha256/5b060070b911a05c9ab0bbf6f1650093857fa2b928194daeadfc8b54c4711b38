/*
 * rt_cms_remainder_probe.c -- RT-CMS-REMAINDER: the Phase-12.9 remainder, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer, a `nonnull`/`null`, a short length, a byte equality or the
 * produced text -- never an address and never a clock.
 *
 * ## What this probe drives
 *
 * The nine hand-offs Phase 12.9 landed, over fixed embedded fixtures only:
 *
 *   * `ASN1_ITEM_get`/`ASN1_ITEM_lookup` (`asn1_item_list.c`) -- a sweep of the generated item
 *     list at fixed indices, past the end, and by name, printing each item's `sname` or `null`.
 *   * `PKCS7_ISSUER_AND_SERIAL_digest` -- a fixed `PKCS7_ISSUER_AND_SERIAL` DER decoded with
 *     `d2i_PKCS7_ISSUER_AND_SERIAL` and digested with `EVP_sha256()`/`EVP_sha1()`.
 *   * `d2i_PKCS7_bio`/`i2d_PKCS7_bio` and `d2i_PKCS7_fp`/`i2d_PKCS7_fp` -- round trips over the
 *     fixed PKCS#7 `signedData` fixture (`rt_pkcs7_der.h`), the re-encoded length, and the
 *     refusal arms with a null BIO and a null value (with and without a prior `*p7`).
 *   * `CTLOG_STORE_load_default_file` -- with `CTLOG_FILE` unset and no default file present, the
 *     returned decision (`0`), plus the missing-explicit-file arm.
 *   * `SMIME_write_ASN1`/`_ex` -- a fixed opaque PKCS#7 value (no `SMIME_DETACHED`, which would
 *     generate a random boundary) written into a memory BIO, the produced MIME text escaped and
 *     compared, and `SMIME_read_ASN1`/`_ex` reading it back.
 *   * `SMIME_text` -- a `Content-Type: text/plain` body (returns 1) and a non-text type (0).
 *   * `X509_load_http`/`X509_CRL_load_http` -- the memory-BIO pattern `rt_http_probe.c` uses: a
 *     `BIO_new_mem_buf`-backed rbio carrying a fixed HTTP 200 whose body is a fixed DER
 *     certificate (`rt_ess_der.h`) or a fixed DER CRL, printing `nonnull` and the subject, plus
 *     the null-url refusal.
 *
 * ## Arms that are deliberately absent
 *
 * The `FILE *` refusal arms `d2i_PKCS7_fp(NULL, ...)` and `i2d_PKCS7_fp(NULL, ...)` are **not
 * driven**: an `ASN1_item_*_fp` call installs the caller's `FILE *` into a `BIO_s_file` and then
 * reads or writes it, so a null `FILE *` dereferences it. Measured against the authority, both
 * segfault; a probe that dies on both sides compares nothing, so the `_fp` refusals here are a
 * bad-content decode (returns `null`) and a null value encode (returns `0`), which reach the same
 * decisions without the dangling `FILE *`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/ct.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "rt_ess_der.h"
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

/* The item's `sname`, or `null` when the item is absent. */
static void out_sname(const char *key, const ASN1_ITEM *it)
{
    printf("%s=%s\n", key, it != NULL ? it->sname : "null");
}

/* A hex rendering of exactly `n` bytes. */
static void out_hex(const char *key, const unsigned char *p, size_t n)
{
    size_t i;

    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* The bytes as one escaped line: printable ASCII verbatim, `\n`/`\r`/`\\` escaped, the rest hex. */
static void out_text(const char *key, const char *p, size_t n)
{
    size_t i;

    printf("%s=", key);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];

        if (c == '\n')
            printf("\\n");
        else if (c == '\r')
            printf("\\r");
        else if (c == '\\')
            printf("\\\\");
        else if (c >= 0x20 && c < 0x7f)
            putchar((int)c);
        else
            printf("\\x%02x", c);
    }
    printf("\n");
}

/* ---------------------------------------------------------------------------------------------
 * Fixed fixtures. The issuer-and-serial is a hand-built DER for a `PKCS7_ISSUER_AND_SERIAL` whose
 * `issuer` is a one-RDN `CN=T` name and whose `serial` is `0x1234`; the CRL is a hand-built
 * `CertificateList` with the same issuer, a fixed `UTCTime` and a `sha256WithRSA` algorithm. Both
 * parse identically on either side, and neither is a function of a clock or a key.
 * --------------------------------------------------------------------------------------------- */

static const unsigned char rt_rem_ias_der[] = {
    0x30, 0x12, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x01, 0x54, 0x02, 0x02, 0x12, 0x34,
};

static const unsigned char rt_rem_crl_der[] = {
    0x30, 0x40,
    0x30, 0x2c,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, 0x54,
    0x17, 0x0d, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x01, 0x00,
};

/* ---------------------------------------------------------------------------------------------
 * `crypto/asn1/asn1_item_list.c` -- the two lookup entry points.
 * --------------------------------------------------------------------------------------------- */

static void arm_item_list(void)
{
    static const size_t idx[] = { 0, 4, 13, 39, 99, 146 };
    static const char *names[] = {
        "X509", "PKCS7", "ASN1_INTEGER", "CMS_ContentInfo", "X509_NAME", "NoSuchItem",
    };
    char key[48];
    size_t i;

    for (i = 0; i < sizeof idx / sizeof idx[0]; i++) {
        snprintf(key, sizeof key, "item.get.%zu", idx[i]);
        out_sname(key, ASN1_ITEM_get(idx[i]));
    }

    /* At and past the generated list's end (147 entries), and far past it. */
    out_sname("item.get.147", ASN1_ITEM_get(147));
    out_sname("item.get.148", ASN1_ITEM_get(148));
    out_sname("item.get.100000", ASN1_ITEM_get(100000));

    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        snprintf(key, sizeof key, "item.lookup.%s", names[i]);
        out_sname(key, ASN1_ITEM_lookup(names[i]));
    }
}

/* ---------------------------------------------------------------------------------------------
 * `PKCS7_ISSUER_AND_SERIAL_digest`.
 * --------------------------------------------------------------------------------------------- */

static void arm_issuer_serial_digest(void)
{
    const unsigned char *p = rt_rem_ias_der;
    PKCS7_ISSUER_AND_SERIAL *ias =
        d2i_PKCS7_ISSUER_AND_SERIAL(NULL, &p, (long)sizeof rt_rem_ias_der);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mlen = 0;
    int ret;

    out_ptr("ias.d2i", ias);
    if (ias == NULL)
        return;

    ERR_clear_error();
    ret = PKCS7_ISSUER_AND_SERIAL_digest(ias, EVP_sha256(), md, &mlen);
    out_int("ias.sha256.ret", ret);
    out_int("ias.sha256.len", (long)mlen);
    out_hex("ias.sha256.md", md, mlen);

    ERR_clear_error();
    mlen = 0;
    ret = PKCS7_ISSUER_AND_SERIAL_digest(ias, EVP_sha1(), md, &mlen);
    out_int("ias.sha1.ret", ret);
    out_int("ias.sha1.len", (long)mlen);
    out_hex("ias.sha1.md", md, mlen);

    /* A null `len` out-slot is accepted by `ASN1_item_digest`, so it is comparable. */
    ERR_clear_error();
    out_int("ias.sha256.nolen",
            PKCS7_ISSUER_AND_SERIAL_digest(ias, EVP_sha256(), md, NULL));

    PKCS7_ISSUER_AND_SERIAL_free(ias);
}

/* ---------------------------------------------------------------------------------------------
 * `d2i_PKCS7_bio`/`i2d_PKCS7_bio` and `d2i_PKCS7_fp`/`i2d_PKCS7_fp` over the fixed signedData.
 * --------------------------------------------------------------------------------------------- */

static void arm_pkcs7_stream(void)
{
    const unsigned char *p = rt_pkcs7_signed_der;
    PKCS7 *p7 = d2i_PKCS7(NULL, &p, (long)rt_pkcs7_signed_der_len);
    PKCS7 *back;
    BIO *mem, *out;
    FILE *fp;
    char *data = NULL;
    long len;

    out_int("pk7.relen", p7 != NULL ? i2d_PKCS7(p7, NULL) : -1);
    out_int("pk7.fixture_len", (long)rt_pkcs7_signed_der_len);

    /* d2i_PKCS7_bio from the fixture, then i2d_PKCS7_bio back. */
    mem = BIO_new_mem_buf(rt_pkcs7_signed_der, (int)rt_pkcs7_signed_der_len);
    ERR_clear_error();
    back = d2i_PKCS7_bio(mem, NULL);
    out_ptr("pk7.bio.d2i", back);
    out_int("pk7.bio.d2i_relen", back != NULL ? i2d_PKCS7(back, NULL) : -1);
    if (back != NULL)
        PKCS7_free(back);
    BIO_free(mem);

    out = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("pk7.bio.i2d", p7 != NULL ? i2d_PKCS7_bio(out, p7) : -1);
    len = (long)BIO_ctrl(out, BIO_CTRL_INFO, 0, &data);
    out_int("pk7.bio.i2d_len", len);
    out_int("pk7.bio.i2d_eq", data != NULL && len == (long)rt_pkcs7_signed_der_len
            && memcmp(data, rt_pkcs7_signed_der, (size_t)len) == 0);
    BIO_free(out);

    /* Refusals: null BIO, with and without a live `*p7` slot to read the context from. */
    ERR_clear_error();
    back = d2i_PKCS7_bio(NULL, NULL);
    out_ptr("pk7.bio.d2i_nullbp", back);
    ERR_clear_error();
    back = p7;
    out_ptr("pk7.bio.d2i_nullbp_ctx", d2i_PKCS7_bio(NULL, &back));
    ERR_clear_error();
    out_int("pk7.bio.i2d_nullval", i2d_PKCS7_bio(BIO_new(BIO_s_mem()), NULL));
    ERR_clear_error();
    out_int("pk7.bio.i2d_nullbp", i2d_PKCS7_bio(NULL, p7));

    /* FILE * arms: a live tmpfile round trip, a bad-content decode and a null-value encode. */
    fp = tmpfile();
    out_ptr("pk7.fp.tmpfile", fp);
    if (fp != NULL) {
        ERR_clear_error();
        out_int("pk7.fp.i2d", p7 != NULL ? i2d_PKCS7_fp(fp, p7) : -1);
        rewind(fp);
        ERR_clear_error();
        back = d2i_PKCS7_fp(fp, NULL);
        out_ptr("pk7.fp.d2i", back);
        out_int("pk7.fp.d2i_relen", back != NULL ? i2d_PKCS7(back, NULL) : -1);
        if (back != NULL)
            PKCS7_free(back);
        ERR_clear_error();
        out_int("pk7.fp.i2d_nullval", i2d_PKCS7_fp(fp, NULL));
        fclose(fp);
    }
    ERR_clear_error();

    fp = tmpfile();
    out_ptr("pk7.fp.bad.tmpfile", fp);
    if (fp != NULL) {
        fputs("not a pkcs7", fp);
        rewind(fp);
        ERR_clear_error();
        back = d2i_PKCS7_fp(fp, NULL);
        out_ptr("pk7.fp.d2i_bad", back);
        PKCS7_free(back);
        fclose(fp);
    }
    ERR_clear_error();

    PKCS7_free(p7);
}

/* ---------------------------------------------------------------------------------------------
 * `CTLOG_STORE_load_default_file`. `CTLOG_FILE` is unset by `main`, so the compile-time default
 * (which is absent in the container) is what this reaches; both sides answer 0.
 * --------------------------------------------------------------------------------------------- */

static void arm_ctlog(void)
{
    CTLOG_STORE *store = CTLOG_STORE_new();

    out_ptr("ct.store", store);
    if (store == NULL)
        return;

    ERR_clear_error();
    out_int("ct.load_default_file.ret", CTLOG_STORE_load_default_file(store));
    ERR_clear_error();
    out_int("ct.load_file_missing.ret", CTLOG_STORE_load_file(store, "/nonexistent/ct.cnf"));
    ERR_clear_error();

    CTLOG_STORE_free(store);
}

/* ---------------------------------------------------------------------------------------------
 * `SMIME_write_ASN1`/`_ex` and `SMIME_read_ASN1`/`_ex`, then `SMIME_text`.
 * --------------------------------------------------------------------------------------------- */

static void write_and_read(const char *tag, ASN1_VALUE *val, int use_ex)
{
    char key[64];
    BIO *out = BIO_new(BIO_s_mem());
    char *data = NULL;
    long len;
    int ret;

    ERR_clear_error();
    if (use_ex)
        ret = SMIME_write_ASN1_ex(out, val, NULL, 0, NID_pkcs7_signed, NID_pkcs7_data,
                                  NULL, PKCS7_it(), NULL, NULL);
    else
        ret = SMIME_write_ASN1(out, val, NULL, 0, NID_pkcs7_signed, NID_pkcs7_data,
                               NULL, PKCS7_it());
    len = (long)BIO_ctrl(out, BIO_CTRL_INFO, 0, &data);

    snprintf(key, sizeof key, "smime.%s.write_ret", tag);
    out_int(key, ret);
    snprintf(key, sizeof key, "smime.%s.write_len", tag);
    out_int(key, len);
    snprintf(key, sizeof key, "smime.%s.text", tag);
    out_text(key, data != NULL ? data : "", data != NULL ? (size_t)len : 0);

    if (data != NULL && len > 0) {
        BIO *in = BIO_new_mem_buf(data, (int)len);
        BIO *bcont = NULL;
        ASN1_VALUE *rt;

        ERR_clear_error();
        rt = SMIME_read_ASN1(in, &bcont, PKCS7_it());
        snprintf(key, sizeof key, "smime.%s.read", tag);
        out_ptr(key, rt);
        snprintf(key, sizeof key, "smime.%s.read_relen", tag);
        out_int(key, rt != NULL ? i2d_PKCS7((PKCS7 *)rt, NULL) : -1);
        PKCS7_free((PKCS7 *)rt);
        BIO_free(in);
        BIO_free(bcont);

        in = BIO_new_mem_buf(data, (int)len);
        bcont = NULL;
        ERR_clear_error();
        rt = SMIME_read_ASN1_ex(in, 0, &bcont, PKCS7_it(), NULL, NULL, NULL);
        snprintf(key, sizeof key, "smime.%s.read_ex", tag);
        out_ptr(key, rt);
        snprintf(key, sizeof key, "smime.%s.read_ex_relen", tag);
        out_int(key, rt != NULL ? i2d_PKCS7((PKCS7 *)rt, NULL) : -1);
        PKCS7_free((PKCS7 *)rt);
        BIO_free(in);
        BIO_free(bcont);
    }

    BIO_free(out);
}

static void arm_smime(void)
{
    const unsigned char *p = rt_pkcs7_signed_der;
    PKCS7 *p7 = d2i_PKCS7(NULL, &p, (long)rt_pkcs7_signed_der_len);
    static const char TEXT[] = "Content-Type: text/plain\r\n\r\nhello";
    static const char NOTEXT[] =
        "Content-Type: application/octet-stream\r\n\r\nhello";
    BIO *in, *out;
    long body;

    out_int("smime.p7_relen", p7 != NULL ? i2d_PKCS7(p7, NULL) : -1);
    if (p7 != NULL) {
        write_and_read("plain", (ASN1_VALUE *)p7, 0);
        write_and_read("ex", (ASN1_VALUE *)p7, 1);
    }

    in = BIO_new_mem_buf(TEXT, (int)strlen(TEXT));
    out = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("smime.text.ret", SMIME_text(in, out));
    body = (long)BIO_ctrl(out, BIO_CTRL_INFO, 0, NULL);
    out_int("smime.text.body_len", body);
    BIO_free(in);
    BIO_free(out);

    in = BIO_new_mem_buf(NOTEXT, (int)strlen(NOTEXT));
    out = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("smime.text.nontext", SMIME_text(in, out));
    out_int("smime.text.nontext_body_len", (long)BIO_ctrl(out, BIO_CTRL_INFO, 0, NULL));
    BIO_free(in);
    BIO_free(out);
    ERR_clear_error();

    PKCS7_free(p7);
}

/* ---------------------------------------------------------------------------------------------
 * `X509_load_http`/`X509_CRL_load_http` over a memory BIO pair.
 * --------------------------------------------------------------------------------------------- */

/* A malloc'd `HTTP/1.1 200` whose body is `body`; the caller owns it. */
static char *http_response(const unsigned char *body, size_t blen, int *out_len)
{
    char hdr[128];
    int hlen = snprintf(hdr, sizeof hdr,
                        "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", blen);
    char *resp = malloc((size_t)hlen + blen);

    memcpy(resp, hdr, (size_t)hlen);
    memcpy(resp + hlen, body, blen);
    *out_len = hlen + (int)blen;
    return resp;
}

static void arm_http(void)
{
    char *resp;
    int rlen;
    BIO *w, *r;
    X509 *x;
    X509_CRL *crl;

    /* X509_load_http with the fixed RSA cert from rt_ess_der.h as the 200 body. */
    resp = http_response(rt_ess_cert_der, sizeof rt_ess_cert_der, &rlen);
    w = BIO_new(BIO_s_mem());
    r = BIO_new_mem_buf(resp, rlen);
    ERR_clear_error();
    x = X509_load_http("http://example.com/cert", w, r, 0);
    out_ptr("http.x509", x);
    if (x != NULL) {
        char cn[128] = { 0 };

        X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof cn);
        out_int("http.x509.cert_len", i2d_X509(x, NULL));
        printf("http.x509.cn=%s\n", cn);
        X509_free(x);
    }
    BIO_free(r);
    BIO_free(w);
    free(resp);
    ERR_clear_error();

    /* X509_CRL_load_http with the fixed CRL. */
    resp = http_response(rt_rem_crl_der, sizeof rt_rem_crl_der, &rlen);
    w = BIO_new(BIO_s_mem());
    r = BIO_new_mem_buf(resp, rlen);
    ERR_clear_error();
    crl = X509_CRL_load_http("http://example.com/crl", w, r, 0);
    out_ptr("http.crl", crl);
    if (crl != NULL) {
        char cn[128] = { 0 };

        X509_NAME_get_text_by_NID(X509_CRL_get_issuer(crl), NID_commonName, cn, sizeof cn);
        out_int("http.crl.crl_len", i2d_X509_CRL(crl, NULL));
        printf("http.crl.cn=%s\n", cn);
        X509_CRL_free(crl);
    }
    BIO_free(r);
    BIO_free(w);
    free(resp);
    ERR_clear_error();

    /* The null-url refusals, on a fresh BIO pair. */
    resp = http_response(rt_ess_cert_der, sizeof rt_ess_cert_der, &rlen);
    w = BIO_new(BIO_s_mem());
    r = BIO_new_mem_buf(resp, rlen);
    ERR_clear_error();
    out_ptr("http.x509.nullurl", X509_load_http(NULL, w, r, 0));
    ERR_clear_error();
    out_ptr("http.crl.nullurl", X509_CRL_load_http(NULL, w, r, 0));
    BIO_free(r);
    BIO_free(w);
    free(resp);
    ERR_clear_error();
}

int main(void)
{
    /* The CT default-file arm is the comparable one only with `CTLOG_FILE` unset, so it is
     * cleared before any OpenSSL call: the transcript must not inherit the runner's environment. */
    unsetenv("CTLOG_FILE");
    setvbuf(stdout, NULL, _IOLBF, 0);
    ERR_clear_error();

    arm_item_list();
    arm_issuer_serial_digest();
    arm_pkcs7_stream();
    arm_ctlog();
    arm_smime();
    arm_http();

    return 0;
}
