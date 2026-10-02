/*
 * RT-X509 -- the Phase 11.7 shared remainder, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell, whose two transcripts are diffed line by line (`phase11_courts.py`). Every
 * observation is a small integer, a `nonnull`/`null`, a byte-for-byte equality, a printed text's
 * length and 64-bit FNV-1a digest, or an error coordinate (`lib.reason`) -- never an address and
 * never an allocator-dependent value.
 *
 * What it drives
 * --------------
 *   * `crypto/asn1/p5_scrypt.c`'s Phase 11 half: the `SCRYPT_PARAMS` item group (`_it`/`_new`/
 *     `_free`/`d2i_`/`i2d_`) over a fixed DER, and `PKCS5_pbe2_set_scrypt` over a fetched
 *     `AES-128-CBC` with a fixed salt and IV so the identifier's bytes are a function of the
 *     library. Its two refusals -- a NULL cipher and an N that scrypt rejects -- are driven too.
 *   * `crypto/evp/evp_lib.c`'s two hand-offs, `EVP_CIPHER_CTX_get_algor` and
 *     `EVP_PKEY_CTX_get_algor`, on fresh contexts whose parameter getter answers nothing: the
 *     `-1` and the empty queue are the observable.
 *   * `crypto/asn1/asn_mstbl.c`'s `ASN1_add_stable_module`: the export is called, then a
 *     configuration naming `stbl_section` is loaded twice -- once with a row the initialiser
 *     accepts and once with a name it cannot resolve -- and the load's answer and error
 *     coordinate are printed.
 *   * `crypto/evp/evp_pkey.c`'s `EVP_PKCS82PKEY_ex`: a fixed PKCS#8 key round-trips back to an
 *     equal `EVP_PKEY`, and a NULL input refuses.
 *   * `crypto/asn1/t_spki.c`'s `NETSCAPE_SPKI_print`: a real `NETSCAPE_SPKI` carrying the fixed
 *     key's public key is printed to a memory BIO and reduced to its length and digest.
 *   * `crypto/pkcs12/p12_mutl.c`'s `PBMAC1_get1_pbkdf2_param`: a fixed `PBMAC1` `AlgorithmIdentifier`
 *     yields the embedded `PBKDF2PARAM`, whose re-encoded bytes are compared, and a
 *     parameter-less identifier refuses with its coordinate.
 *
 * The one fixed key is the RSA private key the Phase 11.6/11.4 probes carry, used only to give the
 * SPKI printer and the PKCS#8 round-trip a real object; its bytes are never printed.
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
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

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

/* A fixed RSA private key, used only to give the SPKI printer and PKCS#8 a real object. */
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
 * A fixed SCRYPT_PARAMS, built from literal DER.
 *
 *   SEQUENCE {                   30 0f
 *     salt OCTET STRING 01020304   04 04 01 02 03 04
 *     costParameter INTEGER 16     02 01 10
 *     blockSize INTEGER 1          02 01 01
 *     parallelizationParameter 1   02 01 01
 *   }
 * --------------------------------------------------------------------------------------------- */

static const unsigned char RT_SCRYPT_DER[] = {
    0x30, 0x0f,
    0x04, 0x04, 0x01, 0x02, 0x03, 0x04,
    0x02, 0x01, 0x10,
    0x02, 0x01, 0x01,
    0x02, 0x01, 0x01,
};

/* ---------------------------------------------------------------------------------------------
 * A fixed `X509_ALGOR` for PBMAC1, built from literal DER.
 *
 *   SEQUENCE {                          30 33
 *     algorithm id-PBMAC1               06 09 2a 86 48 86 f7 0d 01 05 0e
 *     parameters PBMAC1PARAM            30 26
 *       keyDerivationFunc               30 16
 *         id-PBKDF2                     06 09 2a 86 48 86 f7 0d 01 05 0c
 *         PBKDF2PARAM                   30 09 04 04 01 02 03 04 02 01 10
 *       messageAuthScheme               30 0c
 *         hmacWithSHA1                  06 08 2a 86 48 86 f7 0d 02 07
 *         NULL                          05 00
 *   }
 * The embedded PBKDF2PARAM is salt 01020304 and iterationCount 16.
 * --------------------------------------------------------------------------------------------- */

static const unsigned char RT_PBMAC1_ALGOR[] = {
    0x30, 0x33,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0e,
    0x30, 0x26,
    0x30, 0x16,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c,
    0x30, 0x09, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x10,
    0x30, 0x0c,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07,
    0x05, 0x00,
};

/* A PBMAC1 `AlgorithmIdentifier` with no parameter: the NULL-parameter refusal. */
static const unsigned char RT_PBMAC1_NOPARAM[] = {
    0x30, 0x0b,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0e,
};

/* ---------------------------------------------------------------------------------------------
 * `crypto/asn1/p5_scrypt.c` -- the `SCRYPT_PARAMS` item and `PKCS5_pbe2_set_scrypt`.
 * --------------------------------------------------------------------------------------------- */

static void drive_scrypt(void)
{
    unsigned char salt[16], iv[16];
    int i;

    for (i = 0; i < 16; i++) {
        salt[i] = (unsigned char)(i + 1);
        iv[i] = (unsigned char)(0x10 + i);
    }

    ERR_clear_error();
    out_ptr("scrypt.it", (const void *)SCRYPT_PARAMS_it());
    out_ptr("scrypt.new", SCRYPT_PARAMS_new());
    SCRYPT_PARAMS_free(NULL);
    out_int("scrypt.free_null", 1);

    {
        const unsigned char *p = RT_SCRYPT_DER;
        SCRYPT_PARAMS *sp = d2i_SCRYPT_PARAMS(NULL, &p, (long)sizeof RT_SCRYPT_DER);

        out_ptr("scrypt.d2i", sp);
        if (sp != NULL) {
            int len = i2d_SCRYPT_PARAMS(sp, NULL);
            unsigned char *der = OPENSSL_malloc(len);
            unsigned char *q = der;

            i2d_SCRYPT_PARAMS(sp, &q);
            out_hex("scrypt.i2d", der, len);
            out_int("scrypt.i2d.equals_fixture",
                    len == (int)sizeof RT_SCRYPT_DER
                        && memcmp(der, RT_SCRYPT_DER, (size_t)len) == 0);
            OPENSSL_free(der);
            SCRYPT_PARAMS_free(sp);
        }
    }

    {
        EVP_CIPHER *c;
        X509_ALGOR *alg;

        /* The fetched provider cipher takes its legacy NID from the `OBJ_NAME` table, so
         * register a legacy method under that name first; without it the candidate, whose
         * legacy stratum has not populated the table, would refuse with
         * `ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER` for a reason this court is not about. The
         * method is deliberately leaked: `EVP_CIPHER_meth_free` does not unregister it, and
         * freeing it would leave `OBJ_NAME` dangling. */
        {
            EVP_CIPHER *legacy = EVP_CIPHER_meth_new(NID_aes_128_cbc, 16, 16);

            out_int("scrypt.legacy_add", EVP_add_cipher(legacy));
        }
        c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
        out_ptr("scrypt.cipher", c);

        ERR_clear_error();
        alg = PKCS5_pbe2_set_scrypt(c, salt, 16, iv, 16, 1, 1);
        out_ptr("scrypt.pbe2", alg);
        out_err("scrypt.pbe2.err");
        if (alg != NULL) {
            int len = i2d_X509_ALGOR(alg, NULL);
            unsigned char *der = OPENSSL_malloc(len);
            unsigned char *q = der;

            i2d_X509_ALGOR(alg, &q);
            out_hex("scrypt.pbe2.der", der, len);
            OPENSSL_free(der);
            X509_ALGOR_free(alg);
        }

        ERR_clear_error();
        out_ptr("scrypt.pbe2.null_cipher",
                PKCS5_pbe2_set_scrypt(NULL, salt, 16, iv, 16, 1, 1));
        out_err("scrypt.pbe2.null_cipher.err");

        /* N = 3 is not a power of two, so the KDF probe refuses. */
        ERR_clear_error();
        out_ptr("scrypt.pbe2.bad_params",
                PKCS5_pbe2_set_scrypt(c, salt, 16, iv, 3, 1, 1));
        out_err("scrypt.pbe2.bad_params.err");

        EVP_CIPHER_free(c);
    }
}

/* ---------------------------------------------------------------------------------------------
 * `crypto/evp/evp_lib.c` -- the two `X509_ALGOR **` hand-offs.
 *
 * A fresh context whose parameter getter answers nothing is the `-1`, empty-queue arm; a context
 * with no operation is what both sides construct from the public API.
 * --------------------------------------------------------------------------------------------- */

static void drive_algor(void)
{
    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    X509_ALGOR *alg = NULL;

    out_ptr("algor.cctx", cctx);
    out_ptr("algor.pctx", pctx);

    ERR_clear_error();
    out_int("algor.cipher.ret", EVP_CIPHER_CTX_get_algor(cctx, &alg));
    out_ptr("algor.cipher.alg", alg);
    out_err("algor.cipher.err");

    alg = NULL;
    ERR_clear_error();
    out_int("algor.pkey.ret", EVP_PKEY_CTX_get_algor(pctx, &alg));
    out_ptr("algor.pkey.alg", alg);
    out_err("algor.pkey.err");

    X509_ALGOR_free(alg);
    EVP_PKEY_CTX_free(pctx);
    EVP_CIPHER_CTX_free(cctx);
}

/* ---------------------------------------------------------------------------------------------
 * `crypto/asn1/asn_mstbl.c` -- `ASN1_add_stable_module` and its `stbl_section` module.
 * --------------------------------------------------------------------------------------------- */

static CONF *load_conf_text(const char *text)
{
    BIO *b = BIO_new_mem_buf(text, -1);
    CONF *c = NCONF_new(NULL);

    NCONF_load_bio(c, b, NULL);
    BIO_free(b);
    return c;
}

static void drive_stbl(void)
{
    /* The good row changes an OID's string table; the bad row names an unknown OID. */
    static const char good[] =
        "openssl_conf = stbl_cfg\n"
        "\n"
        "[stbl_cfg]\n"
        "stbl_section = my_stbl\n"
        "\n"
        "[my_stbl]\n"
        "description = min:3,max:9\n";
    static const char bad[] =
        "openssl_conf = stbl_cfg\n"
        "\n"
        "[stbl_cfg]\n"
        "stbl_section = my_stbl\n"
        "\n"
        "[my_stbl]\n"
        "rt-no-such-oid-name = min:1\n";

    ASN1_add_stable_module();
    out_int("stbl.add_module", 1);

    ERR_clear_error();
    {
        CONF *c = load_conf_text(good);

        out_ptr("stbl.good.conf", c);
        if (c != NULL) {
            out_int("stbl.good.load", CONF_modules_load(c, NULL, CONF_MFLAGS_NO_DSO));
            out_err("stbl.good.err");
            NCONF_free(c);
        }
    }

    ERR_clear_error();
    {
        CONF *c = load_conf_text(bad);

        out_ptr("stbl.bad.conf", c);
        if (c != NULL) {
            out_int("stbl.bad.load", CONF_modules_load(c, NULL, CONF_MFLAGS_NO_DSO));
            out_err("stbl.bad.err");
            NCONF_free(c);
        }
    }
}

/* ---------------------------------------------------------------------------------------------
 * `crypto/evp/evp_pkey.c` -- `EVP_PKCS82PKEY_ex`.
 * --------------------------------------------------------------------------------------------- */

static void drive_pkcs82pkey(void)
{
    BIO *kb = BIO_new_mem_buf(pkcs8_plain_pem, (int)(sizeof pkcs8_plain_pem - 1));
    EVP_PKEY *k = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(k);

    out_ptr("p82.key", k);
    out_ptr("p82.p8", p8);

    ERR_clear_error();
    {
        EVP_PKEY *back = EVP_PKCS82PKEY_ex(p8, NULL, NULL);

        out_ptr("p82.ex", back);
        if (back != NULL)
            out_int("p82.eq", EVP_PKEY_eq(k, back));
        EVP_PKEY_free(back);
    }

    ERR_clear_error();
    out_ptr("p82.null", EVP_PKCS82PKEY_ex(NULL, NULL, NULL));
    out_err("p82.null.err");

    PKCS8_PRIV_KEY_INFO_free(p8);
    EVP_PKEY_free(k);
    BIO_free(kb);
}

/* ---------------------------------------------------------------------------------------------
 * `crypto/asn1/t_spki.c` -- `NETSCAPE_SPKI_print`.
 * --------------------------------------------------------------------------------------------- */

static void drive_spki(void)
{
    BIO *kb = BIO_new_mem_buf(pkcs8_plain_pem, (int)(sizeof pkcs8_plain_pem - 1));
    EVP_PKEY *k = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
    NETSCAPE_SPKI *spki = NETSCAPE_SPKI_new();

    out_ptr("spki.new", spki);
    out_ptr("spki.key", k);

    if (spki != NULL && k != NULL) {
        out_int("spki.set_pubkey", NETSCAPE_SPKI_set_pubkey(spki, k));
        {
            BIO *b = BIO_new(BIO_s_mem());

            out_int("spki.print", NETSCAPE_SPKI_print(b, spki));
            out_mem("spki.print.out", b);
            BIO_free(b);
        }
    }

    NETSCAPE_SPKI_free(spki);
    EVP_PKEY_free(k);
    BIO_free(kb);
}

/* ---------------------------------------------------------------------------------------------
 * `crypto/pkcs12/p12_mutl.c` -- `PBMAC1_get1_pbkdf2_param`.
 * --------------------------------------------------------------------------------------------- */

static void drive_pbmac1(void)
{
    const unsigned char *p = RT_PBMAC1_ALGOR;
    X509_ALGOR *alg = d2i_X509_ALGOR(NULL, &p, (long)sizeof RT_PBMAC1_ALGOR);
    PBKDF2PARAM *pb;

    out_ptr("pbmac1.alg", alg);

    ERR_clear_error();
    pb = PBMAC1_get1_pbkdf2_param(alg);
    out_ptr("pbmac1.pb", pb);
    out_err("pbmac1.pb.err");
    if (pb != NULL) {
        int len = i2d_PBKDF2PARAM(pb, NULL);
        unsigned char *der = OPENSSL_malloc(len);
        unsigned char *q = der;

        i2d_PBKDF2PARAM(pb, &q);
        out_hex("pbmac1.pb.der", der, len);
        OPENSSL_free(der);
        PBKDF2PARAM_free(pb);
    }
    X509_ALGOR_free(alg);

    {
        const unsigned char *q = RT_PBMAC1_NOPARAM;
        X509_ALGOR *a2 = d2i_X509_ALGOR(NULL, &q, (long)sizeof RT_PBMAC1_NOPARAM);

        out_ptr("pbmac1.noparam.alg", a2);
        ERR_clear_error();
        out_ptr("pbmac1.noparam.pb", PBMAC1_get1_pbkdf2_param(a2));
        out_err("pbmac1.noparam.err");
        X509_ALGOR_free(a2);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    ERR_clear_error();

    drive_scrypt();
    drive_algor();
    drive_pbmac1();
    drive_pkcs82pkey();
    drive_spki();
    drive_stbl();

    return 0;
}
