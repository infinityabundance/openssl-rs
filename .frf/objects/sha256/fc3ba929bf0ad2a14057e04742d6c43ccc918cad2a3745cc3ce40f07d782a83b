/*
 * RT-X509-PEM -- the Phase 11.6 PEM X.509 container surface, driven.
 *
 * docs/PHASE-11-SUBPHASES.md section 3.4 asks for two things and nothing else: the
 * **exact PEM text** a fixed object encodes to, and the **error queue and coordinate**
 * each malformed-input arm refuses with. This probe does both, differentially: it is
 * compiled against the admitted authority and against the candidate distribution shell,
 * run, and the two transcripts are compared line for line. Every observation line is
 * `key=value`; no address is printed.
 *
 * Why the PEM text and not a parsed structure
 * -------------------------------------------
 * Section 3.1 and 3.5: an X.509 object's identity is a DER document and the container
 * is a byte codec. A round trip that only proves the candidate's writer is read by the
 * candidate's reader is not evidence -- it would pass for a crate that invented its own
 * base64. So each writer's output is printed **byte for byte** (newlines escaped as `\n`,
 * non-printables as `\xNN`) and the diff compares those bytes to the authority's. The
 * readers are then shown to consume that same PEM text back to the fixture DER.
 *
 * Fixtures
 * --------
 * The DER fixtures are `rt_x509_der.h`'s (the authority tree's own `root-cert.pem`,
 * `testcrl.pem` and `x509-check.csr`, carried forward from Phase 10.8). The PEM texts
 * below are the authority's own encodings of the same documents and of three generated
 * keys: a PKCS#8 RSA private key (plain and PBES2-encrypted), an EC P-256 public key and
 * a DSA public key. A constant both sides read is the input, never the expectation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
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

/* The first error on the queue as `lib.reason`, keyed `<key>.err`, then the queue is cleared. */
static void out_errq(const char *key)
{
    unsigned long e = ERR_get_error();

    ERR_clear_error();
    if (e == 0) {
        printf("%s.err=none\n", key);
        return;
    }
    printf("%s.err=%d.%d\n", key, ERR_GET_LIB(e), ERR_GET_REASON(e));
}

/* The exact bytes of a PEM document, one `key=...` line: newline and backslash escaped, every
 * other byte literal. A trailing newline is present and significant. */
static void out_pem(const char *key, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", key);
    for (i = 0; i < len; i++) {
        unsigned char c = buf[i];

        if (c == '\n')
            printf("\\n");
        else if (c == '\r')
            printf("\\r");
        else if (c == '\\')
            printf("\\\\");
        else if (c >= 0x20 && c < 0x7f)
            putchar(c);
        else
            printf("\\x%02x", c);
    }
    putchar('\n');
}

/* Print the contents of a memory BIO as an escaped PEM document. */
static void out_mem_pem(const char *key, BIO *b)
{
    char *data = NULL;
    long len = BIO_get_mem_data(b, &data);

    out_pem(key, (const unsigned char *)data, len < 0 ? 0 : (size_t)len);
}

static void out_der_eq(const char *key, const unsigned char *der, int len,
                       const unsigned char *want, unsigned int wantlen)
{
    out_int(key, len > 0 && (unsigned int)len == wantlen
                     && memcmp(der, want, (size_t)len) == 0);
}

/* ---------------------------------------------------------------------------------------------
 * The fixed PEM fixtures.
 * --------------------------------------------------------------------------------------------- */

static const char cert_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDATCCAemgAwIBAgIBATANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdSb290\n"
    "IENBMCAXDTIwMTIxMjIwMDk0OVoYDzIxMjAxMjEzMjAwOTQ5WjASMRAwDgYDVQQD\n"
    "DAdSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4eYA9Qa8\n"
    "oEY4eQ8/HnEZE20C3yubdmv8rLAh7daRCEI7pWM17FJboKJKxdYAlAOXWj25ZyjS\n"
    "feMhXKTtxjyNjoTRnVTDPdl0opZ2Z3H5xhpQd7P9eO5b4OOMiSPCmiLsPtQ3ngfN\n"
    "wCtVERc6NEIcaQ06GLDtFZRexv2eh8Yc55QaksBfBcFzQ+UD3gmRySTO2I6Lfi7g\n"
    "MUjRhipqVSZ66As2Tpex4KTJ2lxpSwOACFaDox+yKrjBTP7FsU3UwAGq7b7OJb3u\n"
    "aa32B81uK6GJVPVo65gJ7clgZsszYkoDsGjWDqtfwTVVfv1G7rrr3Laio+2Ff3ff\n"
    "tWgiQ35mJCOvxQIDAQABo2AwXjAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIB\n"
    "BjAdBgNVHQ4EFgQUjvUlrx6ba4Q9fICayVOcTXL3o1IwHwYDVR0jBBgwFoAUjvUl\n"
    "rx6ba4Q9fICayVOcTXL3o1IwDQYJKoZIhvcNAQELBQADggEBAL2sqYB5P22c068E\n"
    "UNoMAfDgGxnuZ48ddWSWK/OWiS5U5VI7R/c8vjOCHU1OI/eQfhOenXxnHNF2QBuu\n"
    "bjdg5ImPsvgQNFs6ZUgenQh+E4JDkTpn7bKCgtK7qlAPUXZRZI6uAaH5zKu3yFPU\n"
    "2kow3LFCwYutrSfVg6JYeX+cuYsLHFzNzOhqh88Mu9yJ7pPJ8faeHFglHa51eoaw\n"
    "vurAVknk7tzUxLZN0PxD9nrduVwtiluFbCPz0EtP5Dt1KylGdPrKvCJNkFkRJX+S\n"
    "0t9VNIhyqLmslP5uSFtuTt8toXkizaYlxIVHckkvpuKZB8m7l8C/lom9sqagjZ1J\n"
    "If+teEc=\n"
    "-----END CERTIFICATE-----\n";

static const char crl_pem[] =
    "-----BEGIN X509 CRL-----\n"
    "MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT\n"
    "F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy\n"
    "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw\n"
    "MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw\n"
    "MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw\n"
    "MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw\n"
    "MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw\n"
    "MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw\n"
    "MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw\n"
    "NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw\n"
    "NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF\n"
    "AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ\n"
    "wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt\n"
    "JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v\n"
    "-----END X509 CRL-----\n";

static const char req_pem[] =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIICXzCCAUcCAQAwGjEYMBYGA1UEAwwPeDUwOS1jaGVjay10ZXN0MIIBIjANBgkq\n"
    "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAneo6YBYjP2VunQiZRCMZipO6x+zES/d8\n"
    "Ft9qOXbk8LU9XLP8vspX3stJebWAcxjMY1DzXmBkwaors+rnlcjL23t8Mplz6fs8\n"
    "6Gqt4n9ycnG/tYLq0sokKRek9Ty5nyQ4EEE9F5yO6kcByORSU7yjPZqb94iqIQbH\n"
    "k/2vMn3ZNu8xWK0jGY32qmXPtGtfGx4v0oDTd+i4/r5z3LNg80vMpgSddGauonMu\n"
    "sS99LBwyjziiqw/PhCerLlJuQqSy+DeozzppPQ4+10L9mMKF9ktGLOnRaR7hgSdT\n"
    "Z4AVv9GZvaLHgzscaqZTxiGGvJzewSK08ACRIZJikxIvT/ADyIug1QIDAQABoAAw\n"
    "DQYJKoZIhvcNAQELBQADggEBABN+XkwFoyyN1+b5SYhUzdQFj0ZfhzNxiMXOFR/n\n"
    "ww0gW7KCAhZd90aPBtQjEORzsCUX2xhllglXaojw+wOaEMaJDMDzojJelan1TEWJ\n"
    "Vyvklj8OBoH25ur5Y8iWrnMivkb4hU1Mrd4QxF697FVVTniwVyUy8Xfn6D44vEII\n"
    "gyCUk/jCD6MAD6/hBaexetqrbUQyVrtPewYgXrJokRDGDzFlG3jcXvl3CV2iib2X\n"
    "hAbiaAJmlgZwIMeu/60YgJoIWwilG7dYq9hvcpyfQhYXa9BbOz62WRsLvT0Ewue9\n"
    "81kzAkwhfvGauPh/yjP+6K5HY09KdOtg30xtwUtT4IU5yHQ=\n"
    "-----END CERTIFICATE REQUEST-----\n";

static const char ec_pub_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEflQafNTUp4TuHSTC7Cto++WE7He6\n"
    "urpANz6eKKjKpo01OaFwl8cTy/0dMfBDy6poozKDbOFkPOadYg+4d0XWPg==\n"
    "-----END PUBLIC KEY-----\n";

static const char dsa_pub_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBvzCCATQGByqGSM44BAEwggEnAoGBANKfe6upx8auvOmBq7L73bVhji8lEWnU\n"
    "CA02XIkrgMxuKKcz64MZdkHQMfBnzacFoP53wpriM+1nGVtWTbo9wX39TML/TrXu\n"
    "CCSR4ObqmzQgs4BGZoqgSberqwNTZ/w8gvTKSI1uQ3Jqwv+WgBbioRu5Blz63XAg\n"
    "NjCQMycojLr9Ah0A2QmCq/gDhhDZxmEkB+UXJM1AN6UEejpcQZt6gQKBgQCzyAU/\n"
    "patfGxhKM4FJSzwKqIDgmlF6DRLw3vbKDMNcPC6B9X+50wWjd8yRrGFLgNpw0vpv\n"
    "JcO4/OoKyzS9zYSfAZhG6cIYYRITlfmQ3wg4eaOsESeG+lctDqTE/UGGCDTmhxlH\n"
    "Mj/z3J+m/xCeMHjwtNHyRUhNIkLNFo3wEi83HgOBhAACgYATV7Xx7AKcjXkGcBW7\n"
    "573nrZB+5C1nLVzZo15ML7B/Ki3OVLDLidHCiS3Sft2zO40aTirKSdmPizDMSChn\n"
    "A4a2aL72tKZ7IVg91UyjCl/8y+R27HQr3ZEdkfteT+ZoMV+R6Fc6R9lCBQfwljOT\n"
    "tDUHHGFA/79fn4vipBwynKg8Eg==\n"
    "-----END PUBLIC KEY-----\n";

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

static const char pkcs8_enc_pem[] =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIC5TBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQSk53UrkWm51sWy4r\n"
    "Si9V1wICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEG8UDlPDyG6NpycO\n"
    "NnZqRX0EggKALYSrcEnU3uKbBhmNWjS9VZn8qi3hU37dj9eIGh/sRkOyAEUoBeRr\n"
    "xL9Uu9t3xksPnIvjOcKgFtWJoYYqHrj+GtYwrfhtF5kvss0jonR/PWdjYx7fGNOm\n"
    "qqyXCY5n+VFTMb0RHvwE5jlaO0jw/j+9jkRG46kOf+EX3tpy/DMpGidEbWWK1vSq\n"
    "8uLsAHrI1q0yet5b7yyIIrqfk99BhcnzfkOzHzi+mO/VTJ14kg32VVegJjEo9Ogs\n"
    "f98jVlXFrmZ4mryxSnzBU1ZrQzHoSj585CcrBP7nxPFWnu4PF8/mMrSucXPW+b5U\n"
    "s4d2dEvz/hZ5Uo9Y607sYmR/bh1wBHO6yL/gF8jkcLZQjs1hjLWLvqYZm62dfNan\n"
    "5lqVH448Y4xYrShQs55831BUwKt0mjatnJi4l9/2ELHQr/+GbM5Ij34JEqIFyr4p\n"
    "Oj0P/7D059NbGwKozt8LC11dQ+LInK1BUn0mbLhaoMdXo94//m3KNdflf7droghc\n"
    "VG2ngA5vaAvUCv1K3FsFs+EOdxFgctyyKJlK8FzOF3Q82K5qOKXxe1CoA5GDlNoZ\n"
    "KhGldJa74wcEdQ1xG41bU/kV372XAqMCaG9+jxFPyk/r+LedHoN5KZ4KOe44Mye6\n"
    "R5l3tocrNxPGmxxyB5txZ8zxmReF0svcRb1KWf8Cx5rtiHFEuaWPTTTXJou9ovXo\n"
    "2a+0LSzJxkV6eThh8QOM1ZdjMyYscGCN+ssUaCPNDdkDe6Vyvl8y61Ee85pMNlPu\n"
    "tKm3cL4XjM7tJrcXxVOO95sGm+QkHP85CmUUpRyFEYxyqI6eM+Did3KVX3poI4+E\n"
    "rtWxTP7tUHtM0ffKIbM9Ipn3mV4DMmSmYw==\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";

/* Malformed inputs, per section 3.4. */
static const char trunc_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDATCCAemgAwIBAgIBATANBgkqhkiG9w0BAQsFADASMRAw\n"
    "-----END CERTIFICATE-----\n";

static const char wrong_header_pem[] =
    "-----BEGIN FOO-----\n"
    "YWJjZA==\n"
    "-----END FOO-----\n";

static const char bad_b64_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "!!!!\n"
    "-----END CERTIFICATE-----\n";

static const char notpem[] = "this is not a pem document\n";

/* ---------------------------------------------------------------------------------------------
 * The reader arms' malformed-input refusals. Each prints the object answer and the queue's
 * `lib.reason`.
 * --------------------------------------------------------------------------------------------- */

static void arm_read_x509(const char *key, const char *pem, size_t len)
{
    BIO *b = BIO_new_mem_buf(pem, (int)len);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    out_ptr(key, x);
    out_errq(key);
    X509_free(x);
    BIO_free(b);
}

static void arm_read_crl(const char *key, const char *pem, size_t len)
{
    BIO *b = BIO_new_mem_buf(pem, (int)len);
    X509_CRL *x = PEM_read_bio_X509_CRL(b, NULL, NULL, NULL);

    out_ptr(key, x);
    out_errq(key);
    X509_CRL_free(x);
    BIO_free(b);
}

static void arm_read_req(const char *key, const char *pem, size_t len)
{
    BIO *b = BIO_new_mem_buf(pem, (int)len);
    X509_REQ *x = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);

    out_ptr(key, x);
    out_errq(key);
    X509_REQ_free(x);
    BIO_free(b);
}

static void drive_malformed(void)
{
    /* Wrong container: a CRL fed to the certificate reader and vice versa. */
    arm_read_x509("mal.wrong_container.crl_as_x509", crl_pem, sizeof crl_pem - 1);
    arm_read_crl("mal.wrong_container.x509_as_crl", cert_pem, sizeof cert_pem - 1);
    /* Truncated body, wrong header name, invalid base64, and no PEM at all. */
    arm_read_x509("mal.truncated", trunc_pem, sizeof trunc_pem - 1);
    arm_read_x509("mal.wrong_header", wrong_header_pem, sizeof wrong_header_pem - 1);
    arm_read_x509("mal.bad_base64", bad_b64_pem, sizeof bad_b64_pem - 1);
    arm_read_x509("mal.not_pem", notpem, sizeof notpem - 1);
    /* The CRL and request readers refuse the same malformed shapes. */
    arm_read_crl("mal.crl.truncated", trunc_pem, sizeof trunc_pem - 1);
    arm_read_req("mal.req.wrong_header", wrong_header_pem, sizeof wrong_header_pem - 1);
}

/* ---------------------------------------------------------------------------------------------
 * Section 3.4 -- the writers' exact PEM text and the readers' round trip.
 * --------------------------------------------------------------------------------------------- */

static void drive_cert(void)
{
    const unsigned char *p = RT_X509_CERT_DER;
    X509 *x = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    BIO *b;
    X509 *x2;
    unsigned char *der = NULL;
    char *data = NULL;
    long len;
    int dl;

    out_ptr("cert.d2i", x);
    b = BIO_new(BIO_s_mem());
    out_int("cert.write", PEM_write_bio_X509(b, x));
    out_mem_pem("cert.pem", b);
    len = BIO_get_mem_data(b, &data);
    {
        BIO *rb = BIO_new_mem_buf(data, (int)len);

        x2 = PEM_read_bio_X509(rb, NULL, NULL, NULL);
        out_ptr("cert.reread", x2);
        dl = i2d_X509(x2, &der);
        out_int("cert.reread.derlen", dl);
        out_der_eq("cert.reread.der_eq", der, dl, RT_X509_CERT_DER, RT_X509_CERT_DER_LEN);
        OPENSSL_free(der);
        X509_free(x2);
        BIO_free(rb);
    }
    BIO_free(b);

    /* The `FILE *` spelling: write to a temp stream, rewind, read back. */
    {
        FILE *fp = tmpfile();
        X509 *r;

        out_int("cert.write_fp", PEM_write_X509(fp, x));
        rewind(fp);
        r = PEM_read_X509(fp, NULL, NULL, NULL);
        out_ptr("cert.read_fp", r);
        der = NULL;
        dl = i2d_X509(r, &der);
        out_der_eq("cert.read_fp.der_eq", der, dl, RT_X509_CERT_DER, RT_X509_CERT_DER_LEN);
        OPENSSL_free(der);
        X509_free(r);
        fclose(fp);
    }
    X509_free(x);
}

static void drive_crl(void)
{
    const unsigned char *p = RT_X509_CRL_DER;
    X509_CRL *x = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    BIO *b;
    X509_CRL *x2;
    unsigned char *der = NULL;
    char *data = NULL;
    long len;
    int dl;

    out_ptr("crl.d2i", x);
    b = BIO_new(BIO_s_mem());
    out_int("crl.write", PEM_write_bio_X509_CRL(b, x));
    out_mem_pem("crl.pem", b);
    len = BIO_get_mem_data(b, &data);
    {
        BIO *rb = BIO_new_mem_buf(data, (int)len);

        x2 = PEM_read_bio_X509_CRL(rb, NULL, NULL, NULL);
        out_ptr("crl.reread", x2);
        dl = i2d_X509_CRL(x2, &der);
        out_der_eq("crl.reread.der_eq", der, dl, RT_X509_CRL_DER, RT_X509_CRL_DER_LEN);
        OPENSSL_free(der);
        X509_CRL_free(x2);
        BIO_free(rb);
    }
    BIO_free(b);
    {
        FILE *fp = tmpfile();
        X509_CRL *r;

        out_int("crl.write_fp", PEM_write_X509_CRL(fp, x));
        rewind(fp);
        r = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
        out_ptr("crl.read_fp", r);
        der = NULL;
        dl = i2d_X509_CRL(r, &der);
        out_der_eq("crl.read_fp.der_eq", der, dl, RT_X509_CRL_DER, RT_X509_CRL_DER_LEN);
        OPENSSL_free(der);
        X509_CRL_free(r);
        fclose(fp);
    }
    X509_CRL_free(x);
}

static void drive_req(void)
{
    const unsigned char *p = RT_X509_REQ_DER;
    X509_REQ *x = d2i_X509_REQ(NULL, &p, (long)RT_X509_REQ_DER_LEN);
    BIO *b;
    X509_REQ *x2;
    unsigned char *der = NULL;
    char *data = NULL;
    long len;
    int dl;

    out_ptr("req.d2i", x);
    /* The authority's own request PEM text, read back to the fixture DER. */
    {
        BIO *rb = BIO_new_mem_buf(req_pem, (int)(sizeof req_pem - 1));
        X509_REQ *r = PEM_read_bio_X509_REQ(rb, NULL, NULL, NULL);
        unsigned char *d = NULL;
        int dl2 = i2d_X509_REQ(r, &d);

        out_ptr("req.read_authority", r);
        out_der_eq("req.read_authority.der_eq", d, dl2, RT_X509_REQ_DER, RT_X509_REQ_DER_LEN);
        OPENSSL_free(d);
        X509_REQ_free(r);
        BIO_free(rb);
    }
    b = BIO_new(BIO_s_mem());
    out_int("req.write", PEM_write_bio_X509_REQ(b, x));
    out_mem_pem("req.pem", b);
    len = BIO_get_mem_data(b, &data);
    {
        BIO *rb = BIO_new_mem_buf(data, (int)len);

        x2 = PEM_read_bio_X509_REQ(rb, NULL, NULL, NULL);
        out_ptr("req.reread", x2);
        dl = i2d_X509_REQ(x2, &der);
        out_der_eq("req.reread.der_eq", der, dl, RT_X509_REQ_DER, RT_X509_REQ_DER_LEN);
        OPENSSL_free(der);
        X509_REQ_free(x2);
        BIO_free(rb);
    }
    BIO_free(b);

    /* The legacy `NEW CERTIFICATE REQUEST` header, writers only. */
    b = BIO_new(BIO_s_mem());
    out_int("req.write_new", PEM_write_bio_X509_REQ_NEW(b, x));
    out_mem_pem("req.new.pem", b);
    BIO_free(b);
    {
        FILE *fp = tmpfile();

        out_int("req.write_fp", PEM_write_X509_REQ(fp, x));
        rewind(fp);
        x2 = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
        out_ptr("req.read_fp", x2);
        der = NULL;
        dl = i2d_X509_REQ(x2, &der);
        out_der_eq("req.read_fp.der_eq", der, dl, RT_X509_REQ_DER, RT_X509_REQ_DER_LEN);
        OPENSSL_free(der);
        X509_REQ_free(x2);
        fclose(fp);
    }
    {
        FILE *fp = tmpfile();

        out_int("req.write_new_fp", PEM_write_X509_REQ_NEW(fp, x));
        fclose(fp);
    }
    X509_REQ_free(x);
}

static void drive_xaux(void)
{
    const unsigned char *p = RT_X509_CERT_DER;
    X509 *x = d2i_X509_AUX(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    BIO *b;
    X509 *x2;
    unsigned char *der = NULL;
    char *data = NULL;
    long len;
    int dl;

    out_ptr("xaux.d2i", x);
    b = BIO_new(BIO_s_mem());
    out_int("xaux.write", PEM_write_bio_X509_AUX(b, x));
    out_mem_pem("xaux.pem", b);
    len = BIO_get_mem_data(b, &data);
    {
        BIO *rb = BIO_new_mem_buf(data, (int)len);

        x2 = PEM_read_bio_X509_AUX(rb, NULL, NULL, NULL);
        out_ptr("xaux.reread", x2);
        dl = i2d_X509_AUX(x2, &der);
        out_der_eq("xaux.reread.der_eq", der, dl, RT_X509_CERT_DER, RT_X509_CERT_DER_LEN);
        OPENSSL_free(der);
        X509_free(x2);
        BIO_free(rb);
    }
    BIO_free(b);
    {
        FILE *fp = tmpfile();
        X509 *r;

        out_int("xaux.write_fp", PEM_write_X509_AUX(fp, x));
        rewind(fp);
        r = PEM_read_X509_AUX(fp, NULL, NULL, NULL);
        out_ptr("xaux.read_fp", r);
        X509_free(r);
        fclose(fp);
    }
    X509_free(x);
}

/* ---------------------------------------------------------------------------------------------
 * The public-key readers and writers.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509_pubkey(void)
{
    BIO *b = BIO_new_mem_buf(ec_pub_pem, (int)(sizeof ec_pub_pem - 1));
    X509_PUBKEY *xpk = PEM_read_bio_X509_PUBKEY(b, NULL, NULL, NULL);
    BIO *o;
    char *data = NULL;
    long len;

    out_ptr("x509pubkey.read", xpk);
    o = BIO_new(BIO_s_mem());
    out_int("x509pubkey.write", PEM_write_bio_X509_PUBKEY(o, xpk));
    out_mem_pem("x509pubkey.pem", o);
    len = BIO_get_mem_data(o, &data);
    {
        BIO *rb = BIO_new_mem_buf(data, (int)len);
        X509_PUBKEY *x2 = PEM_read_bio_X509_PUBKEY(rb, NULL, NULL, NULL);

        out_ptr("x509pubkey.reread", x2);
        X509_PUBKEY_free(x2);
        BIO_free(rb);
    }
    BIO_free(o);
    {
        FILE *fp = tmpfile();
        X509_PUBKEY *r;

        out_int("x509pubkey.write_fp", PEM_write_X509_PUBKEY(fp, xpk));
        rewind(fp);
        r = PEM_read_X509_PUBKEY(fp, NULL, NULL, NULL);
        out_ptr("x509pubkey.read_fp", r);
        X509_PUBKEY_free(r);
        fclose(fp);
    }
    BIO_free(b);
    X509_PUBKEY_free(xpk);
}

static void drive_rsa_ec_dsa(void)
{
    /* RSA: the certificate's own SubjectPublicKeyInfo. */
    {
        const unsigned char *p = RT_X509_CERT_DER;
        X509 *cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
        EVP_PKEY *pk = X509_get0_pubkey(cert);
        RSA *rsa = EVP_PKEY_get1_RSA(pk);
        BIO *o = BIO_new(BIO_s_mem());
        char *data = NULL;
        long len;
        RSA *r2;

        out_ptr("rsa_pubkey.read_object", rsa);
        out_int("rsa_pubkey.write", PEM_write_bio_RSA_PUBKEY(o, rsa));
        out_mem_pem("rsa_pubkey.pem", o);
        len = BIO_get_mem_data(o, &data);
        {
            BIO *rb = BIO_new_mem_buf(data, (int)len);

            r2 = PEM_read_bio_RSA_PUBKEY(rb, NULL, NULL, NULL);
            out_ptr("rsa_pubkey.reread", r2);
            RSA_free(r2);
            BIO_free(rb);
        }
        BIO_free(o);
        {
            FILE *fp = tmpfile();
            RSA *r;

            out_int("rsa_pubkey.write_fp", PEM_write_RSA_PUBKEY(fp, rsa));
            rewind(fp);
            r = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
            out_ptr("rsa_pubkey.read_fp", r);
            RSA_free(r);
            fclose(fp);
        }
        RSA_free(rsa);
        X509_free(cert);
    }

    /* EC P-256. */
    {
        BIO *b = BIO_new_mem_buf(ec_pub_pem, (int)(sizeof ec_pub_pem - 1));
        EC_KEY *ec = PEM_read_bio_EC_PUBKEY(b, NULL, NULL, NULL);
        BIO *o = BIO_new(BIO_s_mem());
        char *data = NULL;
        long len;
        EC_KEY *r2;

        out_ptr("ec_pubkey.read", ec);
        out_int("ec_pubkey.write", PEM_write_bio_EC_PUBKEY(o, ec));
        out_mem_pem("ec_pubkey.pem", o);
        len = BIO_get_mem_data(o, &data);
        {
            BIO *rb = BIO_new_mem_buf(data, (int)len);

            r2 = PEM_read_bio_EC_PUBKEY(rb, NULL, NULL, NULL);
            out_ptr("ec_pubkey.reread", r2);
            EC_KEY_free(r2);
            BIO_free(rb);
        }
        BIO_free(o);
        {
            FILE *fp = tmpfile();
            EC_KEY *r;

            out_int("ec_pubkey.write_fp", PEM_write_EC_PUBKEY(fp, ec));
            rewind(fp);
            r = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
            out_ptr("ec_pubkey.read_fp", r);
            EC_KEY_free(r);
            fclose(fp);
        }
        EC_KEY_free(ec);
        BIO_free(b);
    }

    /* DSA. */
    {
        BIO *b = BIO_new_mem_buf(dsa_pub_pem, (int)(sizeof dsa_pub_pem - 1));
        DSA *dsa = PEM_read_bio_DSA_PUBKEY(b, NULL, NULL, NULL);
        BIO *o = BIO_new(BIO_s_mem());
        char *data = NULL;
        long len;
        DSA *r2;

        out_ptr("dsa_pubkey.read", dsa);
        out_int("dsa_pubkey.write", PEM_write_bio_DSA_PUBKEY(o, dsa));
        out_mem_pem("dsa_pubkey.pem", o);
        len = BIO_get_mem_data(o, &data);
        {
            BIO *rb = BIO_new_mem_buf(data, (int)len);

            r2 = PEM_read_bio_DSA_PUBKEY(rb, NULL, NULL, NULL);
            out_ptr("dsa_pubkey.reread", r2);
            DSA_free(r2);
            BIO_free(rb);
        }
        BIO_free(o);
        {
            FILE *fp = tmpfile();
            DSA *r;

            out_int("dsa_pubkey.write_fp", PEM_write_DSA_PUBKEY(fp, dsa));
            rewind(fp);
            r = PEM_read_DSA_PUBKEY(fp, NULL, NULL, NULL);
            out_ptr("dsa_pubkey.read_fp", r);
            DSA_free(r);
            fclose(fp);
        }
        DSA_free(dsa);
        BIO_free(b);
    }
}

/* The provided `PUBKEY` writers: the encoder arm for a provided key, the legacy fallback
 * otherwise. Both writers are driven from the certificate's RSA public key. */
static void drive_pubkey_provided(void)
{
    const unsigned char *p = RT_X509_CERT_DER;
    X509 *cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    EVP_PKEY *pk = X509_get0_pubkey(cert);
    BIO *o = BIO_new(BIO_s_mem());
    char *data = NULL;
    long len;

    out_int("pubkey.write", PEM_write_bio_PUBKEY(o, pk));
    out_mem_pem("pubkey.pem", o);
    len = BIO_get_mem_data(o, &data);
    {
        BIO *rb = BIO_new_mem_buf(data, (int)len);
        EVP_PKEY *r = PEM_read_bio_PUBKEY(rb, NULL, NULL, NULL);

        out_ptr("pubkey.reread", r);
        EVP_PKEY_free(r);
        BIO_free(rb);
    }
    BIO_free(o);
    o = BIO_new(BIO_s_mem());
    out_int("pubkey.write_ex", PEM_write_bio_PUBKEY_ex(o, pk, NULL, NULL));
    out_mem_pem("pubkey.ex.pem", o);
    BIO_free(o);
    {
        FILE *fp = tmpfile();

        out_int("pubkey.write_fp", PEM_write_PUBKEY(fp, pk));
        out_int("pubkey.write_fp_ex", PEM_write_PUBKEY_ex(fp, pk, NULL, NULL));
        fclose(fp);
    }
    X509_free(cert);
}

/* ---------------------------------------------------------------------------------------------
 * `IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, ...)` -- `pem_all.c:44`, over `nsseq.c`'s item.
 * --------------------------------------------------------------------------------------------- */

static void drive_nsseq(void)
{
    NETSCAPE_CERT_SEQUENCE *ns = NETSCAPE_CERT_SEQUENCE_new();
    const unsigned char *p = RT_X509_CERT_DER;
    X509 *leaf;
    BIO *o;
    char *data = NULL;
    long len;

    out_ptr("ns.new", ns);
    out_ptr("ns.it", NETSCAPE_CERT_SEQUENCE_it());
    leaf = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    ns->certs = sk_X509_new_null();
    sk_X509_push(ns->certs, leaf);

    o = BIO_new(BIO_s_mem());
    out_int("ns.write", PEM_write_bio_NETSCAPE_CERT_SEQUENCE(o, ns));
    out_mem_pem("ns.pem", o);
    len = BIO_get_mem_data(o, &data);
    {
        BIO *rb = BIO_new_mem_buf(data, (int)len);
        NETSCAPE_CERT_SEQUENCE *ns2 = PEM_read_bio_NETSCAPE_CERT_SEQUENCE(rb, NULL, NULL, NULL);

        out_ptr("ns.reread", ns2);
        out_int("ns.reread.certs", ns2 != NULL ? sk_X509_num(ns2->certs) : -1);
        NETSCAPE_CERT_SEQUENCE_free(ns2);
        BIO_free(rb);
    }
    BIO_free(o);
    /* The item's own `d2i`/`i2d` pair, driven directly so both names have a court edge. */
    {
        unsigned char *der = NULL;
        int dl = i2d_NETSCAPE_CERT_SEQUENCE(ns, &der);
        const unsigned char *q = der;
        NETSCAPE_CERT_SEQUENCE *ns4 = d2i_NETSCAPE_CERT_SEQUENCE(NULL, &q, (long)dl);

        out_int("ns.derlen", dl);
        out_ptr("ns.d2i", ns4);
        out_int("ns.d2i.certs", ns4 != NULL ? sk_X509_num(ns4->certs) : -1);
        NETSCAPE_CERT_SEQUENCE_free(ns4);
        OPENSSL_free(der);
    }
    {
        FILE *fp = tmpfile();
        NETSCAPE_CERT_SEQUENCE *ns3;

        out_int("ns.write_fp", PEM_write_NETSCAPE_CERT_SEQUENCE(fp, ns));
        rewind(fp);
        ns3 = PEM_read_NETSCAPE_CERT_SEQUENCE(fp, NULL, NULL, NULL);
        out_ptr("ns.read_fp", ns3);
        NETSCAPE_CERT_SEQUENCE_free(ns3);
        fclose(fp);
    }
    NETSCAPE_CERT_SEQUENCE_free(ns);
}

/* ---------------------------------------------------------------------------------------------
 * The PKCS#8 readers and writers.
 * --------------------------------------------------------------------------------------------- */

static void drive_pkcs8(void)
{
    /* The unencrypted `PrivateKeyInfo`. */
    {
        BIO *b = BIO_new_mem_buf(pkcs8_plain_pem, (int)(sizeof pkcs8_plain_pem - 1));
        PKCS8_PRIV_KEY_INFO *p8 = PEM_read_bio_PKCS8_PRIV_KEY_INFO(b, NULL, NULL, NULL);
        BIO *o = BIO_new(BIO_s_mem());
        char *data = NULL;
        long len;

        out_ptr("pkcs8inf.read", p8);
        out_int("pkcs8inf.write", PEM_write_bio_PKCS8_PRIV_KEY_INFO(o, p8));
        out_mem_pem("pkcs8inf.pem", o);
        len = BIO_get_mem_data(o, &data);
        {
            BIO *rb = BIO_new_mem_buf(data, (int)len);
            PKCS8_PRIV_KEY_INFO *r = PEM_read_bio_PKCS8_PRIV_KEY_INFO(rb, NULL, NULL, NULL);

            out_ptr("pkcs8inf.reread", r);
            PKCS8_PRIV_KEY_INFO_free(r);
            BIO_free(rb);
        }
        BIO_free(o);
        {
            FILE *fp = tmpfile();
            PKCS8_PRIV_KEY_INFO *r;

            out_int("pkcs8inf.write_fp", PEM_write_PKCS8_PRIV_KEY_INFO(fp, p8));
            rewind(fp);
            r = PEM_read_PKCS8_PRIV_KEY_INFO(fp, NULL, NULL, NULL);
            out_ptr("pkcs8inf.read_fp", r);
            PKCS8_PRIV_KEY_INFO_free(r);
            fclose(fp);
        }
        PKCS8_PRIV_KEY_INFO_free(p8);
        BIO_free(b);
    }

    /* The encrypted `EncryptedPrivateKeyInfo` (`X509_SIG`), read as DER, re-encoded verbatim. */
    {
        BIO *b = BIO_new_mem_buf(pkcs8_enc_pem, (int)(sizeof pkcs8_enc_pem - 1));
        X509_SIG *sig = PEM_read_bio_PKCS8(b, NULL, NULL, NULL);
        BIO *o = BIO_new(BIO_s_mem());
        char *data = NULL;
        long len;

        out_ptr("pkcs8.read", sig);
        out_int("pkcs8.write", PEM_write_bio_PKCS8(o, sig));
        out_mem_pem("pkcs8.pem", o);
        len = BIO_get_mem_data(o, &data);
        {
            BIO *rb = BIO_new_mem_buf(data, (int)len);
            X509_SIG *r = PEM_read_bio_PKCS8(rb, NULL, NULL, NULL);

            out_ptr("pkcs8.reread", r);
            X509_SIG_free(r);
            BIO_free(rb);
        }
        BIO_free(o);
        {
            FILE *fp = tmpfile();
            X509_SIG *r;

            out_int("pkcs8.write_fp", PEM_write_PKCS8(fp, sig));
            rewind(fp);
            r = PEM_read_PKCS8(fp, NULL, NULL, NULL);
            out_ptr("pkcs8.read_fp", r);
            X509_SIG_free(r);
            fclose(fp);
        }
        X509_SIG_free(sig);
        BIO_free(b);
    }
}

/* ---------------------------------------------------------------------------------------------
 * `PEM_X509_INFO_read[_bio]` and `PEM_X509_INFO_write_bio`, over `crypto/asn1/x_info.c`'s item.
 * --------------------------------------------------------------------------------------------- */

static void drive_info(void)
{
    char bundle[8192];
    BIO *b;
    STACK_OF(X509_INFO) *sk;
    int n;
    int i;

    snprintf(bundle, sizeof bundle, "%s%s%s", cert_pem, crl_pem, pkcs8_plain_pem);
    b = BIO_new_mem_buf(bundle, -1);
    sk = PEM_X509_INFO_read_bio(b, NULL, NULL, NULL);
    out_ptr("info.read", sk);
    n = sk != NULL ? sk_X509_INFO_num(sk) : -1;
    out_int("info.num", n);
    for (i = 0; i < n && i < 4; i++) {
        X509_INFO *xi = sk_X509_INFO_value(sk, i);
        char key[64];

        snprintf(key, sizeof key, "info.%d.x509", i);
        out_int(key, xi->x509 != NULL);
        snprintf(key, sizeof key, "info.%d.crl", i);
        out_int(key, xi->crl != NULL);
        snprintf(key, sizeof key, "info.%d.x_pkey", i);
        out_int(key, xi->x_pkey != NULL);
    }
    if (sk != NULL && n > 0) {
        BIO *o = BIO_new(BIO_s_mem());

        out_int("info.write0", PEM_X509_INFO_write_bio(o, sk_X509_INFO_value(sk, 0),
                                                       NULL, NULL, 0, NULL, NULL));
        out_mem_pem("info.0.pem", o);
        BIO_free(o);
    }
    BIO_free(b);

    /* The `_ex` BIO spelling, driven directly so its own name has a court edge. */
    {
        BIO *b2 = BIO_new_mem_buf(bundle, -1);
        STACK_OF(X509_INFO) *s2 = PEM_X509_INFO_read_bio_ex(b2, NULL, NULL, NULL, NULL, NULL);

        out_ptr("info.read_bio_ex", s2);
        out_int("info.read_bio_ex.num", s2 != NULL ? sk_X509_INFO_num(s2) : -1);
        sk_X509_INFO_pop_free(s2, X509_INFO_free);
        BIO_free(b2);
    }
    {
        X509_INFO *xi = X509_INFO_new();
        X509_PKEY *xp = X509_PKEY_new();

        out_ptr("info_new", xi);
        out_ptr("pkey_new", xp);
        X509_INFO_free(xi);
        X509_PKEY_free(xp);
    }

    /* The `FILE *` spellings. */
    {
        FILE *fp = tmpfile();
        STACK_OF(X509_INFO) *s1;

        fwrite(bundle, 1, strlen(bundle), fp);
        rewind(fp);
        s1 = PEM_X509_INFO_read(fp, NULL, NULL, NULL);
        out_ptr("info.read_fp", s1);
        out_int("info.read_fp.num", s1 != NULL ? sk_X509_INFO_num(s1) : -1);
        sk_X509_INFO_pop_free(s1, X509_INFO_free);
        rewind(fp);
        s1 = PEM_X509_INFO_read_ex(fp, NULL, NULL, NULL, NULL, NULL);
        out_ptr("info.read_ex_fp", s1);
        sk_X509_INFO_pop_free(s1, X509_INFO_free);
        fclose(fp);
    }
    sk_X509_INFO_pop_free(sk, X509_INFO_free);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    drive_cert();
    drive_crl();
    drive_req();
    drive_xaux();
    drive_x509_pubkey();
    drive_rsa_ec_dsa();
    drive_pubkey_provided();
    drive_nsseq();
    drive_pkcs8();
    drive_info();
    drive_malformed();

    return 0;
}
