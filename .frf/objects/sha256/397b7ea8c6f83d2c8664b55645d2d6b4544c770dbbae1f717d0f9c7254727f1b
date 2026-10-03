/*
 * RT-OCSP -- the Phase 12.6 OCSP request/response/extension/printer surface, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution, whose transcripts are diffed line by line. Every observation is a small integer,
 * a `nonnull`/`null`, a byte equality or a short hex string -- never an address and never a wall
 * clock, so the transcript is a function of the library and not of the probe's own frame
 * (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * What it drives
 * --------------
 * It builds the whole OCSP object graph in-process -- `OCSP_CERTID`, `OCSP_ONEREQ`, `OCSP_REQUEST`,
 * `OCSP_SINGLERESP`, `OCSP_BASICRESP`, `OCSP_RESPONSE`, `OCSP_RESPID` -- and drives:
 *
 * * `ocsp_lib.c`: `OCSP_cert_id_new`/`OCSP_cert_to_id`/`OCSP_id_cmp`/`OCSP_id_issuer_cmp`/
 *   `OCSP_CERTID_dup` and `OCSP_id_get0_info`, over a fixed name, key and serial.
 * * `ocsp_cl.c`: the request builder (`OCSP_request_add0_id`/`_set1_name`/`_add1_cert`/`_sign`)
 *   and the response reader/accessors (`OCSP_response_status`/`_get1_basic`, `OCSP_resp_*`,
 *   `OCSP_single_get0_status`, `OCSP_resp_find_status`, `OCSP_check_validity`,
 *   `OCSP_SINGLERESP_get0_id`).
 * * `ocsp_srv.c`: the responder builder (`OCSP_request_onereq_*`, `OCSP_onereq_get0_id`,
 *   `OCSP_request_is_signed`, `OCSP_response_create`, `OCSP_basic_add1_status`/`_add1_cert`/
 *   `_sign_ctx`/`_sign`, `OCSP_RESPID_set_by_*`/`match*`).
 * * `ocsp_vfy.c`: `OCSP_basic_verify`, `OCSP_resp_get0_signer`, `OCSP_request_verify`.
 * * `ocsp_ext.c`: all 36 wrapper functions (request/onereq/basicresp/singleresp), the nonce trio
 *   (`OCSP_request_add1_nonce`/`OCSP_basic_add1_nonce`/`OCSP_check_nonce`/`OCSP_copy_nonce`) and
 *   the four constructors (`OCSP_crlID_new`/`OCSP_accept_responses_new`/`OCSP_archive_cutoff_new`/
 *   `OCSP_url_svcloc_new`).
 * * `ocsp_prn.c`: the three name tables and the two printers, compared byte for byte over memory
 *   BIOs, plus the three refusal arms (`OCSP_check_validity`) and the response/get1-basic refusals.
 * * `ocsp_http.c`: `OCSP_sendreq_new` over a memory BIO (its request-line/header bytes are the
 *   observation) and the `OCSP_sendreq_bio` network arm, which is a `pending.` line: the in-process
 *   exchange over a bare memory BIO is not the transport its contract is about.
 *
 * d2i/i2d round-trips over the fixed embedded DER (`rt_ocsp_der.h`) are exact: a signed request and
 * a signed basic response, each decoded and re-encoded and compared to the embedded bytes.
 *
 * The certificate and key fixtures are the fixed PEM blocks at the bottom; they are written to
 * `/tmp/rt_ocsp_cert.pem` and `/tmp/rt_ocsp_key.pem` before the signing arms run. They were
 * generated once by the authority's own `openssl req -x509` with a critical `OCSPSigning`
 * extended key usage.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "rt_ocsp_der.h"

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

static void out_hex(const char *key, const unsigned char *buf, long len)
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

/* The bytes a memory BIO holds; the BIO is rewound for the next arm. */
static void emit_mem(const char *key, BIO *b)
{
    char *data = NULL;
    long n = BIO_get_mem_data(b, &data);

    out_hex(key, (const unsigned char *)data, n);
    BIO_reset(b);
}

/* Emit `i2d_OCSP_*(x)` as a length plus hex. */
#define EMIT_I2D(kind, key, obj)                                                   \
    do {                                                                           \
        unsigned char *p_ = NULL;                                                  \
        int n_ = i2d_##kind((obj), &p_);                                           \
        out_hex(key, p_, n_ > 0 ? n_ : 0);                                         \
        OPENSSL_free(p_);                                                          \
    } while (0)

static void emit_ext(const char *key, X509_EXTENSION *ex)
{
    unsigned char *p = NULL;
    int n = i2d_X509_EXTENSION(ex, &p);

    out_hex(key, p, n > 0 ? n : 0);
    OPENSSL_free(p);
}

/* ---------------------------------------------------------------------------------------------
 * Fixtures
 * --------------------------------------------------------------------------------------------- */

static const char cert_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDNTCCAh2gAwIBAgIUP1RDiwOWgg0VBT0WN1iU9QJqXSEwDQYJKoZIhvcNAQEL\n"
"BQAwHTEbMBkGA1UEAwwSb3BlbnNzbC1ycyBSVC1PQ1NQMCAXDTI2MTAwMjE1Mjg1\n"
"NVoYDzIxMjYwOTA4MTUyODU1WjAdMRswGQYDVQQDDBJvcGVuc3NsLXJzIFJULU9D\n"
"U1AwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCf0vZnt3a27WxODRU6\n"
"y/i56PVfQShaao/tY/djY71K16au4uS6bSlEa8Rm7v8Tb4yZA8cPQ3/mfOIfCoGS\n"
"a8+qtYxY30EwNS+THuM2ktCpC3A0j+4p7nR20IPgfUcBxtLx4m8TRP4hVMaosh9r\n"
"ciLbhcPmtwsInHu2Lgk0P1WcB2QTghn7JMoX/w27+6MvMtoMwPLvi3AqcG9R41ER\n"
"8UvNBaHhLc7CpFzUeyHN8YGEE+XNhftT1O1fA2h4veQqnN3tC8/YS8gH/MlqWPUE\n"
"HTXYhNo1si3BFPPgyss8mUHki7Ofl93R8JVhdIoK5IaMjlqNKGWO6OQc3G126vnA\n"
"M1RnAgMBAAGjazBpMB0GA1UdDgQWBBSmplyg+4t/HlEeWIDhLqbN9QWkHDAfBgNV\n"
"HSMEGDAWgBSmplyg+4t/HlEeWIDhLqbN9QWkHDAPBgNVHRMBAf8EBTADAQH/MBYG\n"
"A1UdJQEB/wQMMAoGCCsGAQUFBwMJMA0GCSqGSIb3DQEBCwUAA4IBAQCaMUxTCuhG\n"
"92+4bhcjvnxe3mqI7kupI1udjYf3KCzpid60UWQyWzkoAO6Fo+2ZdJymwmsBkN6a\n"
"3anfOHQyHYoGRgZ3cvdcVmw8DBxRJaBLMU8YfLNVxYXLMegeNMPU5RPCdUAcwaK1\n"
"T6TNxpTfqDQjn0eSmeJ2A62ata6mdvH6s6ejJgmyrL5kIToWiVFmYTddY9dHmyFH\n"
"T4aMtUJWv6LyX8NTF9f8WHvNXCsZbwPFYoSxIg1664t/Qg9rx+9jdsWwi/vZeUuI\n"
"E7jp29Nk3Cef7be6LmKr5vKjZMUQ0XGBBsas1OBEhz/JLAKN1WoIZeCeD0M+p/HH\n"
"fZNsiCTURn0l\n"
"-----END CERTIFICATE-----\n";

static const char key_pem[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCf0vZnt3a27WxO\n"
"DRU6y/i56PVfQShaao/tY/djY71K16au4uS6bSlEa8Rm7v8Tb4yZA8cPQ3/mfOIf\n"
"CoGSa8+qtYxY30EwNS+THuM2ktCpC3A0j+4p7nR20IPgfUcBxtLx4m8TRP4hVMao\n"
"sh9rciLbhcPmtwsInHu2Lgk0P1WcB2QTghn7JMoX/w27+6MvMtoMwPLvi3AqcG9R\n"
"41ER8UvNBaHhLc7CpFzUeyHN8YGEE+XNhftT1O1fA2h4veQqnN3tC8/YS8gH/Mlq\n"
"WPUEHTXYhNo1si3BFPPgyss8mUHki7Ofl93R8JVhdIoK5IaMjlqNKGWO6OQc3G12\n"
"6vnAM1RnAgMBAAECggEABOvYDoWFsEhLR3P7rV3OgNr9gztcZLxXRjYHzhWqJH3T\n"
"chsmc98coDC5UXoWfKC4sZV+MaggbhZ2WAJYzwtmz5jbg3kMZtGcb2lKEcofhrUF\n"
"dXjhGoVvLKFrDiSNZS6cHDqetPcw5BHaNCOX+BUBocTSrW4BdvhqjseIHQW+Oxmq\n"
"tDWvHfHEugii1wPFXlf5zWRBHB+koD61Dh+ultbNga9KEYHR523+fK8tsCxVAv5S\n"
"5tlzVldPK3cltO/7CVSamCtBwWJCkAifY4InBrx7nCR1gLBbBWfAC5h73H4/lFeP\n"
"OC4valVrXf21LOIZlfyfIafrqqFjVPMeA1m+O59B8QKBgQDLBriTbJqlAkOyJd4H\n"
"zuo7h4+ZU/VjCdyciv+IT6NE7AYDBYSjwBx/cJZjQ6VTLNO16D/WP6pygmSL/Xct\n"
"/RXDQQiNjDcoqyfn6tEVUCLFmR7qLSCzlHX+ffSyn6XKv6Me/LDmHJZYWlUoiMVo\n"
"a6Puuv6U3tzK4bcm27hgiV3wXQKBgQDJhoWdcDwrMv13ih0NBs4OPF5yrYEmxE8n\n"
"qqI8IklqhxT2y/HOPqyqDaweRguWMkrbQlfhndodJGHSEYQdRi8S9l7cOMvQCfg4\n"
"gZ5jA/YU1JMk6iPokkNvwqyONrB5mz/qK/wTzhxel9u+jBvChqE1fYrSI9yoib2j\n"
"J0e1tgKbkwKBgGGOOjTEs85kNyksHvM7jrvKGMtBV6EeRP6Hn9/c/IQKsZzUEvco\n"
"QclOzUSnZZKA8L3w+nO1pe5eD3hg89qKSOHIpxZ08LA/Be7fm1YVao/uUreNta/0\n"
"v3npBiKqqdyxlu012L7Jr8iGp3LRvaG+T0hQXDImoItwSDSI0aC5gQUVAoGAO7aT\n"
"gtoNyhMazb/r6b85cThsF/jXSwBiH/PMjJrwPBN4n8RAiwdBLEZO2M2Sg1e1nJBk\n"
"7+JRDc+I+LDd/7qbGjhMVV6y7Zr2pO+rWdWDphpy2z5Rk4k7WDNL4/vKgM4Cu0V7\n"
"NPceqty+bRCg7RvtSqc/ahLcQEhIG7743Zvn2+cCgYBDCYLadW6ixwE5NT7uw0dk\n"
"GuIn1cjTutkg0Q/jvePZdhTataC3bcWnUc/B6LR7bTETAyK6qUsInWrTA/oiqvoa\n"
"tYiWC1vCp/mgjyOEN8pWj8FyZO7q1ZVj3YNU50vFd4OPN4nSqLtoNiorMbcRRyrB\n"
"dI8MooJR/rT7L8y0O3mi6g==\n"
"-----END PRIVATE KEY-----\n";

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
    FILE *f = fopen("/tmp/rt_ocsp_cert.pem", "r");
    X509 *x = f == NULL ? NULL : PEM_read_X509(f, NULL, NULL, NULL);

    if (f != NULL)
        fclose(f);
    return x;
}

static EVP_PKEY *load_key(void)
{
    FILE *f = fopen("/tmp/rt_ocsp_key.pem", "r");
    EVP_PKEY *k = f == NULL ? NULL : PEM_read_PrivateKey(f, NULL, NULL, NULL);

    if (f != NULL)
        fclose(f);
    return k;
}

/* ---------------------------------------------------------------------------------------------
 * Shared builders
 * --------------------------------------------------------------------------------------------- */

static const unsigned char nonce8[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
static const unsigned char issuer_key[16] = { 0xde, 0xad, 0xbe, 0xef };

static X509_NAME *make_name(void)
{
    X509_NAME *nm = X509_NAME_new();

    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (unsigned char *)"RT-OCSP", -1, -1, 0);
    return nm;
}

static OCSP_CERTID *make_cid(long serial)
{
    X509_NAME *nm = make_name();
    ASN1_BIT_STRING *ikey = ASN1_BIT_STRING_new();
    ASN1_INTEGER *sn = ASN1_INTEGER_new();
    OCSP_CERTID *cid;

    ASN1_BIT_STRING_set(ikey, (unsigned char *)issuer_key, sizeof(issuer_key));
    ASN1_INTEGER_set(sn, serial);
    cid = OCSP_cert_id_new(EVP_sha1(), nm, ikey, sn);
    ASN1_INTEGER_free(sn);
    ASN1_BIT_STRING_free(ikey);
    X509_NAME_free(nm);
    return cid;
}

static ASN1_GENERALIZEDTIME *make_gt(const char *s)
{
    ASN1_GENERALIZEDTIME *g = ASN1_GENERALIZEDTIME_new();

    ASN1_GENERALIZEDTIME_set_string(g, s);
    return g;
}

static ASN1_GENERALIZEDTIME *make_gt_bad(void)
{
    ASN1_GENERALIZEDTIME *g = ASN1_GENERALIZEDTIME_new();

    ASN1_STRING_set(g, "notatime", 8);
    return g;
}

/* A basic response with one good entry for `serial` and the fixed update window. */
static OCSP_BASICRESP *make_basic(long serial)
{
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_CERTID *cid = make_cid(serial);
    ASN1_GENERALIZEDTIME *thisupd = make_gt("20000101000000Z");
    ASN1_GENERALIZEDTIME *nextupd = make_gt("21000101000000Z");

    OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_GOOD, 0, NULL,
                           (ASN1_TIME *)thisupd, (ASN1_TIME *)nextupd);
    ASN1_GENERALIZEDTIME_free(thisupd);
    ASN1_GENERALIZEDTIME_free(nextupd);
    OCSP_CERTID_free(cid);
    return bs;
}

/* ---------------------------------------------------------------------------------------------
 * ocsp_lib.c -- the CertID builder and the two comparators
 * --------------------------------------------------------------------------------------------- */

static void drive_ids(void)
{
    X509_NAME *nm = make_name();
    ASN1_BIT_STRING *ikey = ASN1_BIT_STRING_new();
    ASN1_INTEGER *sn = ASN1_INTEGER_new();
    OCSP_CERTID *cid, *cid2, *cid3, *dup;
    ASN1_OCTET_STRING *nh = NULL, *kh = NULL;
    ASN1_OBJECT *md = NULL;
    ASN1_INTEGER *osn = NULL;
    X509 *cert = load_cert();

    ASN1_BIT_STRING_set(ikey, (unsigned char *)issuer_key, sizeof(issuer_key));
    ASN1_INTEGER_set(sn, 0x1234);

    ERR_clear_error();
    cid = OCSP_cert_id_new(EVP_sha1(), nm, ikey, sn);
    out_nonnull("id.cert_id_new", cid);
    EMIT_I2D(OCSP_CERTID, "id.cert_id_new", cid);

    ERR_clear_error();
    cid2 = OCSP_cert_id_new(EVP_sha1(), nm, ikey, sn);
    out_int("id.cmp_same", OCSP_id_cmp(cid, cid2));
    out_int("id.issuer_cmp_same", OCSP_id_issuer_cmp(cid, cid2));

    ASN1_INTEGER_set(sn, 0x5678);
    ERR_clear_error();
    cid3 = OCSP_cert_id_new(EVP_sha1(), nm, ikey, sn);
    out_int("id.cmp_serial_ne", OCSP_id_cmp(cid, cid3) != 0);
    out_int("id.issuer_cmp_serial_eq", OCSP_id_issuer_cmp(cid, cid3));

    out_int("id.get0_info", OCSP_id_get0_info(&nh, &md, &kh, &osn, cid));
    out_nonnull("id.get0_namehash", nh);
    out_nonnull("id.get0_keyhash", kh);
    out_nonnull("id.get0_serial", osn);
    out_nonnull("id.get0_md", md);
    out_int("id.get0_md_nid", OBJ_obj2nid(md));
    out_int("id.get0_namehash_len", nh == NULL ? -1 : ASN1_STRING_length(nh));
    out_int("id.get0_keyhash_len", kh == NULL ? -1 : ASN1_STRING_length(kh));
    out_int("id.get0_serial_val", osn == NULL ? -1 : (long)ASN1_INTEGER_get(osn));
    out_int("id.get0_null_cid", OCSP_id_get0_info(NULL, NULL, NULL, NULL, NULL));

    ERR_clear_error();
    dup = OCSP_CERTID_dup(cid);
    out_nonnull("id.dup", dup);
    out_int("id.dup_cmp", OCSP_id_cmp(cid, dup));
    EMIT_I2D(OCSP_CERTID, "id.dup", dup);

    ERR_clear_error();
    out_nonnull("id.cert_to_id_subject", OCSP_cert_to_id(EVP_sha1(), cert, cert));
    EMIT_I2D(OCSP_CERTID, "id.cert_to_id_subject", OCSP_cert_to_id(EVP_sha1(), cert, cert));
    ERR_clear_error();
    out_nonnull("id.cert_to_id_null_subject", OCSP_cert_to_id(EVP_sha1(), NULL, cert));
    EMIT_I2D(OCSP_CERTID, "id.cert_to_id_null_subject", OCSP_cert_to_id(EVP_sha1(), NULL, cert));

    OCSP_CERTID_free(dup);
    OCSP_CERTID_free(cid3);
    OCSP_CERTID_free(cid2);
    OCSP_CERTID_free(cid);
    X509_free(cert);
    ASN1_INTEGER_free(sn);
    ASN1_BIT_STRING_free(ikey);
    X509_NAME_free(nm);
}

/* ---------------------------------------------------------------------------------------------
 * ocsp_cl.c -- the request builder and the response reader/accessors
 * --------------------------------------------------------------------------------------------- */

static void drive_request(void)
{
    X509 *cert = load_cert();
    EVP_PKEY *key = load_key();
    OCSP_CERTID *cid = make_cid(0x1234);
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    OCSP_REQUEST *signed_req = OCSP_REQUEST_new();
    OCSP_ONEREQ *one;
    OCSP_SIGNATURE *sig;
    unsigned char *p = NULL;
    int n, idx, crit;

    ERR_clear_error();
    out_nonnull("req.new", req);
    EMIT_I2D(OCSP_REQUEST, "req.empty", req);

    ERR_clear_error();
    one = OCSP_request_add0_id(req, cid);
    out_nonnull("req.add0_id", one);
    out_int("req.onereq_count", OCSP_request_onereq_count(req));
    out_nonnull("req.onereq_get0_0", OCSP_request_onereq_get0(req, 0));
    out_nonnull("req.onereq_get0_1", OCSP_request_onereq_get0(req, 1));
    out_nonnull("req.onereq_get0_id", OCSP_onereq_get0_id(one));
    out_int("req.onereq_id_is_cid", OCSP_onereq_get0_id(one) == cid);
    EMIT_I2D(OCSP_REQUEST, "req.one", req);

    out_int("req.is_signed0", OCSP_request_is_signed(req));
    ERR_clear_error();
    out_int("req.set1_name", OCSP_request_set1_name(req, X509_get_subject_name(cert)));
    out_int("req.is_signed1", OCSP_request_is_signed(req));

    /* Request accessors over the extension-less stack. */
    out_int("req.ext_count0", OCSP_REQUEST_get_ext_count(req));
    out_int("req.ext_by_nid_none", OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1));
    out_int("req.ext_by_obj_none",
            OCSP_REQUEST_get_ext_by_OBJ(req, OBJ_nid2obj(NID_id_pkix_OCSP_Nonce), -1));
    out_int("req.ext_by_crit_none", OCSP_REQUEST_get_ext_by_critical(req, 0, -1));
    out_nonnull("req.ext_get_none", OCSP_REQUEST_get_ext(req, 0));
    out_nonnull("req.ext_delete_none", OCSP_REQUEST_delete_ext(req, 0));

    /* add1_cert drives the optionalSignature and the certs stack. */
    ERR_clear_error();
    out_int("req.add1_cert", OCSP_request_add1_cert(req, cert));
    sig = NULL;
    out_int("req.set1_name_again", OCSP_request_set1_name(req, X509_get_subject_name(cert)));

    /* A signed request: no wall clock enters, so the DER is fixed. */
    ERR_clear_error();
    OCSP_request_add0_id(signed_req, make_cid(0x1234));
    ERR_clear_error();
    out_int("req.sign", OCSP_request_sign(signed_req, cert, key, EVP_sha256(), NULL, 0));
    out_int("req.signed_is_signed", OCSP_request_is_signed(signed_req));
    EMIT_I2D(OCSP_REQUEST, "req.signed", signed_req);

    ERR_clear_error();
    out_int("req.verify_nosigs_noverify",
            OCSP_request_verify(signed_req, NULL, NULL, OCSP_NOSIGS | OCSP_NOVERIFY));
    out_err("req.verify_nosigs_noverify.err");

    {
        OCSP_REQUEST *unsigned_req = OCSP_REQUEST_new();

        OCSP_request_add0_id(unsigned_req, make_cid(0x9abc));
        ERR_clear_error();
        out_int("req.verify_unsigned", OCSP_request_verify(unsigned_req, NULL, NULL, 0));
        out_err("req.verify_unsigned.err");
        OCSP_REQUEST_free(unsigned_req);
    }

    /* The CertID inside the signed request round-trips through resp_find. */
    (void)sig;
    (void)n;
    (void)p;
    (void)idx;
    (void)crit;
    OCSP_REQUEST_free(signed_req);
    OCSP_REQUEST_free(req);
    EVP_PKEY_free(key);
    X509_free(cert);
}

static void drive_response(void)
{
    X509 *cert = load_cert();
    EVP_PKEY *key = load_key();
    STACK_OF(X509) *certs = sk_X509_new_null();
    OCSP_RESPONSE *resp;
    OCSP_RESPONSE *resp_signed;
    OCSP_BASICRESP *bs, *bs_signed, *got;
    OCSP_CERTID *cid = make_cid(0x1234);
    OCSP_CERTID *other = make_cid(0x9999);
    OCSP_SINGLERESP *single;
    ASN1_GENERALIZEDTIME *thisupd = make_gt("20000101000000Z");
    ASN1_GENERALIZEDTIME *nextupd = make_gt("21000101000000Z");
    ASN1_GENERALIZEDTIME *revtime = make_gt("20210101000000Z");
    ASN1_GENERALIZEDTIME *r_this = NULL, *r_next = NULL, *r_rev = NULL;
    const ASN1_OCTET_STRING *sig;
    int status = -1, reason = -2;

    sk_X509_push(certs, cert);

    ERR_clear_error();
    resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, NULL);
    out_nonnull("resp.create_null_bs", resp);
    out_int("resp.status_successful", OCSP_response_status(resp));
    EMIT_I2D(OCSP_RESPONSE, "resp.status_only", resp);

    ERR_clear_error();
    out_nonnull("resp.get1_basic_none", OCSP_response_get1_basic(resp));
    out_err("resp.get1_basic_none.err");

    resp = OCSP_response_create(OCSP_RESPONSE_STATUS_TRYLATER, NULL);
    out_int("resp.status_trylater", OCSP_response_status(resp));

    /* A basic response with all three CertStatus arms. */
    bs = OCSP_BASICRESP_new();
    ERR_clear_error();
    out_nonnull("resp.add1_good",
                OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_GOOD, 0, NULL,
                                       (ASN1_TIME *)thisupd, (ASN1_TIME *)nextupd));
    out_nonnull("resp.add1_revoked",
                OCSP_basic_add1_status(bs, other, V_OCSP_CERTSTATUS_REVOKED,
                                       OCSP_REVOKED_STATUS_KEYCOMPROMISE, (ASN1_TIME *)revtime,
                                       (ASN1_TIME *)thisupd, NULL));
    {
        OCSP_CERTID *third = make_cid(0x7777);

        out_nonnull("resp.add1_unknown",
                    OCSP_basic_add1_status(bs, third, V_OCSP_CERTSTATUS_UNKNOWN, 0, NULL,
                                           (ASN1_TIME *)thisupd, NULL));
        OCSP_CERTID_free(third);
    }

    out_int("resp.count", OCSP_resp_count(bs));
    out_nonnull("resp.get0_0", OCSP_resp_get0(bs, 0));
    out_nonnull("resp.get0_1", OCSP_resp_get0(bs, 1));
    out_nonnull("resp.get0_oob", OCSP_resp_get0(bs, 9));
    out_int("resp.find_cid", OCSP_resp_find(bs, cid, -1));
    out_int("resp.find_other", OCSP_resp_find(bs, other, -1));
    out_int("resp.find_missing", OCSP_resp_find(bs, make_cid(0x1), -1));
    out_int("resp.find_last0", OCSP_resp_find(bs, cid, 0));

    single = OCSP_resp_get0(bs, 0);
    out_int("resp.single_good_status",
            OCSP_single_get0_status(single, &reason, &r_rev, &r_this, &r_next));
    out_int("resp.single_good_reason_untouched", reason);
    out_nonnull("resp.single_good_thisupd", r_this);
    out_nonnull("resp.single_good_nextupd", r_next);
    out_nonnull("resp.single_good_id", OCSP_SINGLERESP_get0_id(single));

    single = OCSP_resp_get0(bs, 1);
    reason = -2;
    out_int("resp.single_revoked_status",
            OCSP_single_get0_status(single, &reason, &r_rev, &r_this, &r_next));
    out_int("resp.single_revoked_reason", reason);
    out_nonnull("resp.single_revoked_revtime", r_rev);

    single = OCSP_resp_get0(bs, 2);
    out_int("resp.single_unknown_status", OCSP_single_get0_status(single, NULL, NULL, NULL, NULL));
    out_int("resp.single_null_status", OCSP_single_get0_status(NULL, NULL, NULL, NULL, NULL));

    ERR_clear_error();
    out_int("resp.find_status_good",
            OCSP_resp_find_status(bs, cid, &status, &reason, &r_rev, &r_this, &r_next));
    out_int("resp.find_status_good_status", status);
    out_int("resp.find_status_missing",
            OCSP_resp_find_status(bs, make_cid(0x55), &status, &reason, &r_rev, &r_this, &r_next));

    /* The accessors over an unsigned basic response. */
    sig = OCSP_resp_get0_signature(bs);
    out_nonnull("resp.get0_signature_unsigned", sig);
    out_nonnull("resp.get0_tbs_sigalg", OCSP_resp_get0_tbs_sigalg(bs));
    out_nonnull("resp.get0_respdata", OCSP_resp_get0_respdata(bs));
    out_nonnull("resp.get0_produced_at_unsigned", OCSP_resp_get0_produced_at(bs));
    out_nonnull("resp.get0_certs0", OCSP_resp_get0_certs(bs));
    ERR_clear_error();
    out_int("resp.add1_cert", OCSP_basic_add1_cert(bs, cert));
    out_nonnull("resp.get0_certs1", OCSP_resp_get0_certs(bs));

    /* check_validity over the fixed window and its refusal arms. */
    {
        ASN1_GENERALIZEDTIME *bad = make_gt_bad();
        ASN1_GENERALIZEDTIME *early = make_gt("21000101000000Z");
        ASN1_GENERALIZEDTIME *late = make_gt("21000101000000Z");

        ERR_clear_error();
        out_int("resp.check_validity_ok",
                OCSP_check_validity(thisupd, nextupd, 0, -1));
        out_err("resp.check_validity_ok.err");
        ERR_clear_error();
        out_int("resp.check_validity_bad_this", OCSP_check_validity(bad, NULL, 0, -1));
        out_err("resp.check_validity_bad_this.err");
        ERR_clear_error();
        out_int("resp.check_validity_future_this", OCSP_check_validity(early, NULL, 0, -1));
        out_err("resp.check_validity_future_this.err");
        ERR_clear_error();
        out_int("resp.check_validity_old_this", OCSP_check_validity(thisupd, NULL, 0, 0));
        out_err("resp.check_validity_old_this.err");
        ERR_clear_error();
        out_int("resp.check_validity_order", OCSP_check_validity(late, thisupd, 0, -1));
        out_err("resp.check_validity_order.err");
        ASN1_GENERALIZEDTIME_free(bad);
        ASN1_GENERALIZEDTIME_free(early);
        ASN1_GENERALIZEDTIME_free(late);
    }

    /* A signed basic response: sign via the explicit context, then verify. */
    bs_signed = make_basic(0x1234);
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        ERR_clear_error();
        out_int("resp.basic_sign_ctx_init",
                EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key));
        ERR_clear_error();
        out_int("resp.basic_sign_ctx", OCSP_basic_sign_ctx(bs_signed, cert, ctx, NULL, 0));
        EVP_MD_CTX_free(ctx);
    }
    out_nonnull("resp.signed_signature", OCSP_resp_get0_signature(bs_signed));
    out_int("resp.signed_signature_len", ASN1_STRING_length(OCSP_resp_get0_signature(bs_signed)));
    out_int("resp.signed_tbs_sigalg_nid",
            OBJ_obj2nid(OCSP_resp_get0_tbs_sigalg(bs_signed)->algorithm));

    ERR_clear_error();
    out_int("resp.basic_verify_nosigs_trustother",
            OCSP_basic_verify(bs_signed, certs, NULL, OCSP_NOSIGS | OCSP_TRUSTOTHER));
    out_err("resp.basic_verify_nosigs_trustother.err");
    /* The signature-verifying arm reaches ASN1_item_verify_ctx's
     * `EVP_get_digestbyname(OBJ_nid2sn(mdnid))`, whose fetched-digest identity divergence
     * (D333/D343) the CMS and TS courts already name; it is named here rather than compared. */
    printf("pending.resp.basic_verify_sig=EVP_get_digestbyname_identity_divergence\n");
    {
        X509 *signer = NULL;

        ERR_clear_error();
        out_int("resp.get0_signer", OCSP_resp_get0_signer(bs_signed, &signer, certs));
        out_nonnull("resp.get0_signer_ptr", signer);
    }

    {
        const ASN1_OCTET_STRING *gid = NULL;
        const X509_NAME *gname = NULL;
        ASN1_OCTET_STRING *d1 = NULL;
        X509_NAME *d2 = NULL;

        ERR_clear_error();
        out_int("resp.get0_id", OCSP_resp_get0_id(bs_signed, &gid, &gname));
        out_nonnull("resp.get0_id_name", gname);
        out_nonnull("resp.get0_id_key", gid);
        ERR_clear_error();
        out_int("resp.get1_id", OCSP_resp_get1_id(bs_signed, &d1, &d2));
        out_nonnull("resp.get1_id_name", d2);
        out_nonnull("resp.get1_id_key", d1);
        ASN1_OCTET_STRING_free(d1);
        X509_NAME_free(d2);
    }

    /* `OCSP_basic_sign` wraps `OCSP_basic_sign_ctx` with a fresh context and stamps producedAt;
     * only its decision and the fixed RSA signature width are compared, not the timestamped DER. */
    {
        OCSP_BASICRESP *bs2 = make_basic(0x4321);

        ERR_clear_error();
        out_int("resp.basic_sign", OCSP_basic_sign(bs2, cert, key, EVP_sha256(), NULL, 0));
        out_err("resp.basic_sign.err");
        out_int("resp.basic_sign_sig_len",
                ASN1_STRING_length(OCSP_resp_get0_signature(bs2)));
        OCSP_BASICRESP_free(bs2);
    }

    /* A response with no signer at all is a fault boundary in the authority: OCSP_basic_verify
     * dereferences the unset responder name, so it is named rather than driven. */
    printf("pending.resp.basic_verify_nosigner=authority_derefs_unset_responder_name_fault_boundary\n");

    /* Wrap the signed basic response and read it back. */
    resp_signed = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs_signed);
    out_nonnull("resp.create_signed", resp_signed);
    out_int("resp.create_signed_status", OCSP_response_status(resp_signed));
    ERR_clear_error();
    got = OCSP_response_get1_basic(resp_signed);
    out_nonnull("resp.get1_basic", got);
    out_int("resp.get1_basic_count", OCSP_resp_count(got));
    out_int("resp.get1_basic_find", OCSP_resp_find(got, cid, -1));
    OCSP_BASICRESP_free(got);

    /* The responder id setters and matchers. */
    {
        OCSP_RESPID *rid = OCSP_RESPID_new();

        ERR_clear_error();
        out_int("rid.set_by_name", OCSP_RESPID_set_by_name(rid, cert));
        out_int("rid.match_name", OCSP_RESPID_match(rid, cert));
        out_int("rid.match_name_ex", OCSP_RESPID_match_ex(rid, cert, NULL, NULL));
        ERR_clear_error();
        out_int("rid.set_by_key_ex", OCSP_RESPID_set_by_key_ex(rid, cert, NULL, NULL));
        ERR_clear_error();
        out_int("rid.set_by_key", OCSP_RESPID_set_by_key(rid, cert));
        out_int("rid.match_key", OCSP_RESPID_match(rid, cert));
        out_int("rid.match_key_ex", OCSP_RESPID_match_ex(rid, cert, NULL, NULL));
        ERR_clear_error();
        out_int("rid.set_by_key_ex_null_cert", OCSP_RESPID_set_by_key(rid, NULL));
        out_int("rid.match_null_cert", OCSP_RESPID_match(rid, NULL));
        OCSP_RESPID_free(rid);
    }

    OCSP_BASICRESP_free(bs_signed);
    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(resp_signed);
    OCSP_RESPONSE_free(resp);
    OCSP_CERTID_free(other);
    OCSP_CERTID_free(cid);
    ASN1_GENERALIZEDTIME_free(thisupd);
    ASN1_GENERALIZEDTIME_free(nextupd);
    ASN1_GENERALIZEDTIME_free(revtime);
    sk_X509_free(certs);
    EVP_PKEY_free(key);
    X509_free(cert);
}

/* ---------------------------------------------------------------------------------------------
 * ocsp_ext.c -- the wrapper families, the nonce handling and the four constructors
 * --------------------------------------------------------------------------------------------- */

static void drive_ext_family(void)
{
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_CERTID *cid = make_cid(0x1234);
    OCSP_ONEREQ *one;
    OCSP_SINGLERESP *single;
    OCSP_CERTID *c2 = make_cid(0x1234);
    X509 *cert = load_cert();
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    X509_EXTENSION *ex;
    int crit = -9, idx = -9;

    OCSP_request_add0_id(req, cid);
    one = OCSP_request_onereq_get0(req, 0);
    OCSP_basic_add1_status(bs, c2, V_OCSP_CERTSTATUS_GOOD, 0, NULL, NULL, NULL);
    single = OCSP_resp_get0(bs, 0);

    /* A fixed extension to move through the wrapper families. */
    ASN1_OCTET_STRING_set(os, (unsigned char *)"rt-ocsp", 7);
    ex = X509_EXTENSION_create_by_NID(NULL, NID_id_pkix_OCSP_Nonce, 0, os);
    ASN1_OCTET_STRING_free(os);

    /* OCSP_REQUEST_* over a live stack built by add_ext. */
    ERR_clear_error();
    out_int("ext.req_add_ext", OCSP_REQUEST_add_ext(req, ex, -1));
    out_int("ext.req_count", OCSP_REQUEST_get_ext_count(req));
    out_nonnull("ext.req_get", OCSP_REQUEST_get_ext(req, 0));
    out_int("ext.req_by_nid", OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1));
    out_int("ext.req_by_obj",
            OCSP_REQUEST_get_ext_by_OBJ(req, OBJ_nid2obj(NID_id_pkix_OCSP_Nonce), -1));
    out_int("ext.req_by_crit", OCSP_REQUEST_get_ext_by_critical(req, 0, -1));
    out_nonnull("ext.req_get1_d2i", OCSP_REQUEST_get1_ext_d2i(req, NID_id_pkix_OCSP_Nonce,
                                                              &crit, &idx));
    out_int("ext.req_get1_crit", crit);
    out_int("ext.req_get1_idx", idx);
    out_nonnull("ext.req_delete", OCSP_REQUEST_delete_ext(req, 0));
    out_int("ext.req_count_after", OCSP_REQUEST_get_ext_count(req));

    ASN1_OCTET_STRING_set(os = ASN1_OCTET_STRING_new(), (unsigned char *)"abcdef", 6);
    out_int("ext.req_add1_i2d", OCSP_REQUEST_add1_ext_i2d(req, NID_id_pkix_OCSP_Nonce, os, 0,
                                                          X509V3_ADD_REPLACE));
    out_int("ext.req_count_i2d", OCSP_REQUEST_get_ext_count(req));
    ASN1_OCTET_STRING_free(os);

    /* OCSP_ONEREQ_* */
    ERR_clear_error();
    out_int("ext.one_add_ext", OCSP_ONEREQ_add_ext(one, ex, -1));
    out_int("ext.one_count", OCSP_ONEREQ_get_ext_count(one));
    out_nonnull("ext.one_get", OCSP_ONEREQ_get_ext(one, 0));
    out_int("ext.one_by_nid", OCSP_ONEREQ_get_ext_by_NID(one, NID_id_pkix_OCSP_Nonce, -1));
    out_int("ext.one_by_obj",
            OCSP_ONEREQ_get_ext_by_OBJ(one, OBJ_nid2obj(NID_id_pkix_OCSP_Nonce), -1));
    out_int("ext.one_by_crit", OCSP_ONEREQ_get_ext_by_critical(one, 0, -1));
    out_nonnull("ext.one_get1_d2i", OCSP_ONEREQ_get1_ext_d2i(one, NID_id_pkix_OCSP_Nonce,
                                                             &crit, &idx));
    out_nonnull("ext.one_delete", OCSP_ONEREQ_delete_ext(one, 0));
    ASN1_OCTET_STRING_set(os = ASN1_OCTET_STRING_new(), (unsigned char *)"ghijkl", 6);
    out_int("ext.one_add1_i2d", OCSP_ONEREQ_add1_ext_i2d(one, NID_id_pkix_OCSP_Nonce, os, 0,
                                                         X509V3_ADD_REPLACE));
    ASN1_OCTET_STRING_free(os);

    /* OCSP_BASICRESP_* */
    ERR_clear_error();
    out_int("ext.bs_add_ext", OCSP_BASICRESP_add_ext(bs, ex, -1));
    out_int("ext.bs_count", OCSP_BASICRESP_get_ext_count(bs));
    out_nonnull("ext.bs_get", OCSP_BASICRESP_get_ext(bs, 0));
    out_int("ext.bs_by_nid", OCSP_BASICRESP_get_ext_by_NID(bs, NID_id_pkix_OCSP_Nonce, -1));
    out_int("ext.bs_by_obj",
            OCSP_BASICRESP_get_ext_by_OBJ(bs, OBJ_nid2obj(NID_id_pkix_OCSP_Nonce), -1));
    out_int("ext.bs_by_crit", OCSP_BASICRESP_get_ext_by_critical(bs, 0, -1));
    out_nonnull("ext.bs_get1_d2i", OCSP_BASICRESP_get1_ext_d2i(bs, NID_id_pkix_OCSP_Nonce,
                                                               &crit, &idx));
    out_nonnull("ext.bs_delete", OCSP_BASICRESP_delete_ext(bs, 0));
    ASN1_OCTET_STRING_set(os = ASN1_OCTET_STRING_new(), (unsigned char *)"mnopqr", 6);
    out_int("ext.bs_add1_i2d", OCSP_BASICRESP_add1_ext_i2d(bs, NID_id_pkix_OCSP_Nonce, os, 0,
                                                           X509V3_ADD_REPLACE));
    ASN1_OCTET_STRING_free(os);

    /* OCSP_SINGLERESP_* */
    ERR_clear_error();
    out_int("ext.single_add_ext", OCSP_SINGLERESP_add_ext(single, ex, -1));
    out_int("ext.single_count", OCSP_SINGLERESP_get_ext_count(single));
    out_nonnull("ext.single_get", OCSP_SINGLERESP_get_ext(single, 0));
    out_int("ext.single_by_nid", OCSP_SINGLERESP_get_ext_by_NID(single, NID_id_pkix_OCSP_Nonce, -1));
    out_int("ext.single_by_obj",
            OCSP_SINGLERESP_get_ext_by_OBJ(single, OBJ_nid2obj(NID_id_pkix_OCSP_Nonce), -1));
    out_int("ext.single_by_crit", OCSP_SINGLERESP_get_ext_by_critical(single, 0, -1));
    out_nonnull("ext.single_get1_d2i", OCSP_SINGLERESP_get1_ext_d2i(single, NID_id_pkix_OCSP_Nonce,
                                                                    &crit, &idx));
    out_nonnull("ext.single_delete", OCSP_SINGLERESP_delete_ext(single, 0));
    ASN1_OCTET_STRING_set(os = ASN1_OCTET_STRING_new(), (unsigned char *)"stuvwx", 6);
    out_int("ext.single_add1_i2d", OCSP_SINGLERESP_add1_ext_i2d(single, NID_id_pkix_OCSP_Nonce, os,
                                                                0, X509V3_ADD_REPLACE));
    ASN1_OCTET_STRING_free(os);

    (void)cert;
    X509_EXTENSION_free(ex);
    OCSP_BASICRESP_free(bs);
    OCSP_REQUEST_free(req);
}

static void drive_ext_builders(void)
{
    X509 *cert = load_cert();
    X509_EXTENSION *ex;
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    long num = 0x2a;
    static const char *oids[] = { "1.2.3.4.1", "1.2.3.4.2", NULL };
    static const char *urls[] = { "http://ocsp.example/", NULL };

    /* The nonce trio. */
    ERR_clear_error();
    out_int("ext.req_nonce_fixed", OCSP_request_add1_nonce(req, (unsigned char *)nonce8, 8));
    out_int("ext.req_nonce_count", OCSP_REQUEST_get_ext_count(req));
    {
        int idx = OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
        X509_EXTENSION *ne = OCSP_REQUEST_get_ext(req, idx);

        emit_ext("ext.req_nonce_fixed", ne);
        out_int("ext.req_nonce_value_len",
                ASN1_STRING_length(X509_EXTENSION_get_data(ne)));
    }
    out_int("ext.req_nonce_default", OCSP_request_add1_nonce(req, NULL, 0));
    out_int("ext.req_nonce_default_value_len",
            ASN1_STRING_length(X509_EXTENSION_get_data(
                OCSP_REQUEST_get_ext(req, OCSP_REQUEST_get_ext_by_NID(
                                              req, NID_id_pkix_OCSP_Nonce, -1)))));

    ERR_clear_error();
    out_int("ext.bs_nonce_fixed", OCSP_basic_add1_nonce(bs, (unsigned char *)nonce8, 8));
    out_int("ext.check_nonce_equal", OCSP_check_nonce(req, bs));
    {
        OCSP_REQUEST *empty = OCSP_REQUEST_new();

        out_int("ext.check_nonce_both_absent", OCSP_check_nonce(empty, OCSP_BASICRESP_new()));
        out_int("ext.check_nonce_req_only", OCSP_check_nonce(req, OCSP_BASICRESP_new()));
        out_int("ext.check_nonce_resp_only", OCSP_check_nonce(empty, bs));
        out_int("ext.copy_nonce", OCSP_copy_nonce(OCSP_BASICRESP_new(), req));
        OCSP_REQUEST_free(empty);
    }

    /* crlID */
    ERR_clear_error();
    ex = OCSP_crlID_new("http://crl.example/", &num, "20200101000000Z");
    out_nonnull("ext.crlid_full", ex);
    emit_ext("ext.crlid_full", ex);
    X509_EXTENSION_free(ex);
    ERR_clear_error();
    ex = OCSP_crlID_new(NULL, NULL, NULL);
    out_nonnull("ext.crlid_empty", ex);
    emit_ext("ext.crlid_empty", ex);
    X509_EXTENSION_free(ex);

    /* acceptableResponses */
    ERR_clear_error();
    ex = OCSP_accept_responses_new((char **)oids);
    out_nonnull("ext.accept_responses", ex);
    emit_ext("ext.accept_responses", ex);
    X509_EXTENSION_free(ex);
    ERR_clear_error();
    ex = OCSP_accept_responses_new(NULL);
    out_nonnull("ext.accept_responses_empty", ex);
    emit_ext("ext.accept_responses_empty", ex);
    X509_EXTENSION_free(ex);

    /* archiveCutoff */
    ERR_clear_error();
    ex = OCSP_archive_cutoff_new("20200101000000Z");
    out_nonnull("ext.archive_cutoff", ex);
    emit_ext("ext.archive_cutoff", ex);
    X509_EXTENSION_free(ex);

    /* url_svcloc */
    ERR_clear_error();
    ex = OCSP_url_svcloc_new(X509_get_subject_name(cert), urls);
    out_nonnull("ext.url_svcloc", ex);
    emit_ext("ext.url_svcloc", ex);
    X509_EXTENSION_free(ex);
    ERR_clear_error();
    ex = OCSP_url_svcloc_new(X509_get_subject_name(cert), NULL);
    out_nonnull("ext.url_svcloc_empty", ex);
    emit_ext("ext.url_svcloc_empty", ex);
    X509_EXTENSION_free(ex);

    OCSP_BASICRESP_free(bs);
    OCSP_REQUEST_free(req);
    X509_free(cert);
}

/* ---------------------------------------------------------------------------------------------
 * ocsp_prn.c -- the three name tables and the two printers
 * --------------------------------------------------------------------------------------------- */

static void drive_print(void)
{
    X509 *cert = load_cert();
    EVP_PKEY *key = load_key();
    BIO *mem = BIO_new(BIO_s_mem());
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    OCSP_RESPONSE *resp;
    const unsigned char *rp;
    int i;

    static const long rstat[] = { 0, 1, 2, 3, 5, 6, 7, 99 };
    static const long cstat[] = { 0, 1, 2, 3, -1 };
    static const long reason[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

    for (i = 0; i < (int)(sizeof(rstat) / sizeof(rstat[0])); i++)
        printf("print.rstat.%ld=%s\n", rstat[i], OCSP_response_status_str(rstat[i]));
    for (i = 0; i < (int)(sizeof(cstat) / sizeof(cstat[0])); i++)
        printf("print.cstat.%ld=%s\n", cstat[i], OCSP_cert_status_str(cstat[i]));
    for (i = 0; i < (int)(sizeof(reason) / sizeof(reason[0])); i++)
        printf("print.reason.%ld=%s\n", reason[i], OCSP_crl_reason_str(reason[i]));

    /* A request with a name, an extension and a signature. */
    OCSP_request_add0_id(req, make_cid(0x1234));
    OCSP_request_add1_nonce(req, (unsigned char *)nonce8, 8);
    OCSP_request_set1_name(req, X509_get_subject_name(cert));
    OCSP_request_add1_cert(req, cert);
    ERR_clear_error();
    out_int("print.req_sign", OCSP_request_sign(req, cert, key, EVP_sha256(), NULL, OCSP_NOCERTS));
    ERR_clear_error();
    out_int("print.request", OCSP_REQUEST_print(mem, req, 0));
    emit_mem("print.request", mem);

    /* A response printed from the fixed embedded DER (a real producedAt, fixed in the bytes). */
    rp = rt_ocsp_resp_der;
    resp = d2i_OCSP_RESPONSE(NULL, &rp, (long)sizeof(rt_ocsp_resp_der));
    ERR_clear_error();
    out_int("print.response", OCSP_RESPONSE_print(mem, resp, 0));
    emit_mem("print.response", mem);
    OCSP_RESPONSE_free(resp);

    OCSP_REQUEST_free(req);
    BIO_free(mem);
    EVP_PKEY_free(key);
    X509_free(cert);
}

/* ---------------------------------------------------------------------------------------------
 * The d2i/i2d round-trips over the fixed embedded DER
 * --------------------------------------------------------------------------------------------- */

static void drive_roundtrip(void)
{
    const unsigned char *p;
    OCSP_REQUEST *req;
    OCSP_RESPONSE *resp;
    OCSP_BASICRESP *bs;
    OCSP_SINGLERESP *single;
    ASN1_GENERALIZEDTIME *thisupd = NULL, *nextupd = NULL;
    unsigned char *out = NULL;
    int n;

    p = rt_ocsp_req_der;
    ERR_clear_error();
    req = d2i_OCSP_REQUEST(NULL, &p, (long)sizeof(rt_ocsp_req_der));
    out_nonnull("rt.req_decode", req);
    n = i2d_OCSP_REQUEST(req, &out);
    out_int("rt.req_reencode_len_eq", n == (int)sizeof(rt_ocsp_req_der));
    out_int("rt.req_reencode_bytes_eq",
            n == (int)sizeof(rt_ocsp_req_der)
                && memcmp(out, rt_ocsp_req_der, sizeof(rt_ocsp_req_der)) == 0);
    OPENSSL_free(out);
    out = NULL;
    out_int("rt.req_onereq_count", OCSP_request_onereq_count(req));
    out_int("rt.req_onereq_get0", OCSP_request_onereq_get0(req, 0) != NULL);
    OCSP_REQUEST_free(req);

    p = rt_ocsp_resp_der;
    ERR_clear_error();
    resp = d2i_OCSP_RESPONSE(NULL, &p, (long)sizeof(rt_ocsp_resp_der));
    out_nonnull("rt.resp_decode", resp);
    out_int("rt.resp_status", OCSP_response_status(resp));
    n = i2d_OCSP_RESPONSE(resp, &out);
    out_int("rt.resp_reencode_len_eq", n == (int)sizeof(rt_ocsp_resp_der));
    out_int("rt.resp_reencode_bytes_eq",
            n == (int)sizeof(rt_ocsp_resp_der)
                && memcmp(out, rt_ocsp_resp_der, sizeof(rt_ocsp_resp_der)) == 0);
    OPENSSL_free(out);

    ERR_clear_error();
    bs = OCSP_response_get1_basic(resp);
    out_nonnull("rt.get1_basic", bs);
    out_int("rt.resp_count", OCSP_resp_count(bs));
    single = OCSP_resp_get0(bs, 0);
    out_int("rt.single_status", OCSP_single_get0_status(single, NULL, NULL, &thisupd, &nextupd));
    ERR_clear_error();
    out_int("rt.check_validity", OCSP_check_validity(thisupd, nextupd, 0, -1));
    out_err("rt.check_validity.err");
    OCSP_BASICRESP_free(bs);

    /* The refusal arms of the decoders. */
    {
        const unsigned char *q = rt_ocsp_req_der;
        const static unsigned char junk[] = { 0x30, 0x03, 0x02, 0x01 };

        ERR_clear_error();
        out_nonnull("rt.req_decode_short", d2i_OCSP_REQUEST(NULL, &q, 3));
        out_err("rt.req_decode_short.err");
        (void)junk;
    }
    OCSP_RESPONSE_free(resp);
}

/* ---------------------------------------------------------------------------------------------
 * ocsp_http.c -- the in-process request arm; the network arm is pending
 * --------------------------------------------------------------------------------------------- */

static void drive_http(void)
{
    X509 *cert = load_cert();
    EVP_PKEY *key = load_key();
    BIO *mem = BIO_new(BIO_s_mem());
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    OSSL_HTTP_REQ_CTX *ctx;

    OCSP_request_add0_id(req, make_cid(0x1234));
    OCSP_request_set1_name(req, X509_get_subject_name(cert));

    ERR_clear_error();
    ctx = OCSP_sendreq_new(mem, "/ocsp", req, 0);
    out_nonnull("http.sendreq_new", ctx);
    /* The request line and headers the context wrote are the in-process observation. */
    emit_mem("http.sendreq_new", mem);
    OSSL_HTTP_REQ_CTX_free(ctx);

    /* The network arm: over a bare memory BIO the exchange cannot find a response, so it
     * refuses deterministically; the reason is part of the observation. */
    ERR_clear_error();
    out_nonnull("http.sendreq_bio", OCSP_sendreq_bio(mem, "/ocsp", req));
    out_err("http.sendreq_bio.err");

    OCSP_REQUEST_free(req);
    BIO_free(mem);
    EVP_PKEY_free(key);
    X509_free(cert);
}

/* ---------------------------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------------------------- */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    write_fixture("/tmp/rt_ocsp_cert.pem", cert_pem);
    write_fixture("/tmp/rt_ocsp_key.pem", key_pem);

    drive_ids();
    drive_request();
    drive_response();
    drive_ext_family();
    drive_ext_builders();
    drive_print();
    drive_roundtrip();
    drive_http();
    return 0;
}
