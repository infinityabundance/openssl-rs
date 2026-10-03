/*
 * RT-ESS -- the Phase 12.7 ESS signing-certificate surface (`ess.h`), driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution, whose transcripts are diffed line by line. Every observation is a small integer, a
 * `nonnull`/`null`, a byte equality, a length or a short hex string -- never an address and never a
 * wall clock, so the transcript is a function of the library and not of the probe's own frame
 * (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * What it drives
 * --------------
 * `crypto/ess/ess_asn1.c`'s five item groups -- `ESS_ISSUER_SERIAL`, `ESS_CERT_ID`,
 * `ESS_SIGNING_CERT`, `ESS_CERT_ID_V2`, `ESS_SIGNING_CERT_V2` -- through their `_new`/`_it`/`i2d`/
 * `d2i`/`_dup`/`_free` quintets, over the fixed X509 certificate the probe embeds. Their encodings
 * are a function of the library alone, so the two sides' bytes must agree exactly.
 *
 * `crypto/ess/ess_lib.c`'s three exports: `OSSL_ESS_signing_cert_new_init` and
 * `OSSL_ESS_signing_cert_v2_new_init` over the fixed signer certificate (v1 hashing with SHA-1, v2
 * with SHA-256 -- its default -- and with SHA-1, which carries an explicit `hashAlgorithm`), and
 * `OSSL_ESS_check_signing_certs` over a one-certificate chain for both the v1 and v2 structures,
 * plus its two refusal arms (the attribute absent while required, and no chain match).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/ess.h>
#include <openssl/evp.h>
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
    FILE *f = fopen("/tmp/rt_ess_cert.pem", "r");
    X509 *x = f == NULL ? NULL : PEM_read_X509(f, NULL, NULL, NULL);

    if (f != NULL)
        fclose(f);
    return x;
}

/* ---------------------------------------------------------------------------------------------
 * Item groups -- new/i2d/d2i/dup/free over a fresh value.
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
            kind *c_ = kind##_dup(a_);                                             \
            out_nonnull(#kind ".d2i", b_);                                         \
            out_nonnull(#kind ".dup", c_);                                         \
            out_int(#kind ".consumed", (long)(q_ - p_));                           \
            kind##_free(b_);                                                       \
            kind##_free(c_);                                                       \
        } else {                                                                   \
            out_err(#kind ".i2d.err");                                             \
        }                                                                          \
        kind##_free(a_);                                                           \
        OPENSSL_free(p_);                                                          \
    } while (0)

/* ---------------------------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------------------------- */

int main(void)
{
    X509 *cert;
    STACK_OF(X509) *chain;
    ESS_SIGNING_CERT *sc = NULL;
    ESS_SIGNING_CERT_V2 *scv2 = NULL;
    unsigned char *der = NULL;
    const unsigned char *q;
    int n;

    ERR_clear_error();
    write_fixture("/tmp/rt_ess_cert.pem", rt_ess_cert_pem);
    write_fixture("/tmp/rt_ess_key.pem", rt_ess_key_pem);
    cert = load_cert();
    out_nonnull("cert.load", cert);

    /* --- the item groups: their generated lifecycles over a fresh value --- */
    ROUNDTRIP(ESS_ISSUER_SERIAL);
    ROUNDTRIP(ESS_CERT_ID);
    ROUNDTRIP(ESS_SIGNING_CERT);
    ROUNDTRIP(ESS_CERT_ID_V2);
    ROUNDTRIP(ESS_SIGNING_CERT_V2);

    out_nonnull("ESS_SIGNING_CERT_it", (const void *)ESS_SIGNING_CERT_it());
    out_nonnull("ESS_SIGNING_CERT_V2_it", (const void *)ESS_SIGNING_CERT_V2_it());

    /* --- the builders --- */
    sc = OSSL_ESS_signing_cert_new_init(cert, NULL, 1);
    out_nonnull("v1.sc", sc);
    if (sc != NULL) {
        n = i2d_ESS_SIGNING_CERT(sc, &der);
        out_len_hex("v1.sc.der", der, n > 0 ? n : 0);
        if (n > 0) {
            q = der;
            out_nonnull("v1.sc.rt", d2i_ESS_SIGNING_CERT(NULL, &q, n));
        }
        OPENSSL_free(der);
        der = NULL;
    }

    /* v2 with SHA-256 is the DEFAULT, so its hashAlgorithm is absent. */
    out_int("isa.sha256", EVP_MD_is_a(EVP_sha256(), "SHA256"));
    scv2 = OSSL_ESS_signing_cert_v2_new_init(EVP_sha256(), cert, NULL, 1);
    out_nonnull("v2.sha256.sc", scv2);
    if (scv2 != NULL) {
        n = i2d_ESS_SIGNING_CERT_V2(scv2, &der);
        out_len_hex("v2.sha256.sc.der", der, n > 0 ? n : 0);
        if (n > 0) {
            q = der;
            out_nonnull("v2.sha256.sc.rt", d2i_ESS_SIGNING_CERT_V2(NULL, &q, n));
        }
        OPENSSL_free(der);
        der = NULL;
    }

    /* v2 with SHA-1 is not the default, so its hashAlgorithm is present. */
    {
        ESS_SIGNING_CERT_V2 *v2sha1 =
            OSSL_ESS_signing_cert_v2_new_init(EVP_sha1(), cert, NULL, 1);

        out_nonnull("v2.sha1.sc", v2sha1);
        if (v2sha1 != NULL) {
            n = i2d_ESS_SIGNING_CERT_V2(v2sha1, &der);
            out_len_hex("v2.sha1.sc.der", der, n > 0 ? n : 0);
            OPENSSL_free(der);
            der = NULL;
            ESS_SIGNING_CERT_V2_free(v2sha1);
        }
    }

    /* --- the checker over a one-certificate chain --- */
    chain = sk_X509_new_null();
    if (cert != NULL && chain != NULL) {
        X509_up_ref(cert);
        sk_X509_push(chain, cert);
    }
    out_int("chain.num", chain == NULL ? -1 : (long)sk_X509_num(chain));

    out_int("check.v1.require",
            OSSL_ESS_check_signing_certs(sc, NULL, chain, 1));
    out_int("check.v2.require",
            OSSL_ESS_check_signing_certs(NULL, scv2, chain, 1));
    out_int("check.both.require",
            OSSL_ESS_check_signing_certs(sc, scv2, chain, 1));

    /* the attribute is absent while required: the refusal arm. */
    out_int("check.absent.require",
            OSSL_ESS_check_signing_certs(NULL, NULL, chain, 1));
    out_err("check.absent.err");

    /* ... and when it is not required, the absent attribute is accepted. */
    out_int("check.absent.optional",
            OSSL_ESS_check_signing_certs(NULL, NULL, chain, 0));

    ESS_SIGNING_CERT_free(sc);
    ESS_SIGNING_CERT_V2_free(scv2);
    sk_X509_pop_free(chain, X509_free);
    X509_free(cert);
    EVP_cleanup();
    return 0;
}
