/*
 * openssl-rs -- Phase 10, subphases 10.2 and 10.3's differential court: RT-PKCS12.
 *
 * Compiled twice -- once against the admitted authority, once against the candidate
 * distribution shell -- and run; the two transcripts are compared line for line by
 * `forensics/tools/phase10_courts.py`. Every observation is a `key=value` line, so a missing or
 * extra line costs exactly one residual.
 *
 * What it establishes, and what it does not
 * -----------------------------------------
 * The container's identity is a DER document, not a parsed structure (docs/PHASE-10-SUBPHASES.md
 * section 3.2). This probe drives the three item groups 10.2 lands -- `PKCS12_SAFEBAG`,
 * `PKCS12_BAGS` and `PKCS12_MAC_DATA` -- and prints their **bytes**, built from fixed inputs, and
 * it drives the accessor surface, the refcount/ownership behaviour and the refusal arms with their
 * error coordinates. It does **not** print a parsed structure and call that agreement.
 *
 * Since 10.3 it also drives the four exports of that subphase whose closure is landed:
 * `PKCS12_item_pack_safebag` (a fixed `PKCS8_PRIV_KEY_INFO` packed as a `certBag`, printed as
 * DER), the two `PKCS12_decrypt_skey` spellings (a shrouded key bag with a non-PBE algorithm, so
 * the refusal and its error coordinate are the observation), and `PKCS12_add_secret` (the `add_*`
 * surface, including the stack the call builds and the bag's DER).
 *
 * The second 10.3 slice lands the rest of the subphase, and its arms here are the container's own
 * identity as a DER document (section 3.2): `PKCS12_set_mac`/`PKCS12_gen_mac`/
 * `PKCS12_verify_mac` over a **fixed** salt and iteration count (the `MacData`'s
 * `digestAlgorithm`/`salt`/`iterations` are read back through `PKCS12_get0_mac`, the recomputed
 * MAC is printed, and the `PFX` bytes are compared); `PKCS12_set_pbmac1_pbkdf2` over fixed
 * parameters; `PKCS12_pack_p7encdata(_ex)` over a fixed salt/iteration (the encrypted octets are
 * printed, since a PKCS#5 v1.5 cipher's IV is derived from the salt); `PKCS12_add_key(_ex)` over a
 * fixed RSA `EVP_PKEY` decoded from the shared fixed key set (the unencrypted `keyBag` arm, so the
 * bytes are fixed); `PKCS12_add_safe(_ex)` (its plain arm's bytes, its default-PBE arm's structure);
 * and `PKCS12_newpass` (the password change over a fixed-salt MAC, its result verified both ways).
 *
 * The `PKCS12` container itself (`PKCS12_it`, `i2d_PKCS12`, the `d2i_PKCS12*`/`i2d_PKCS12*_bio/fp`
 * spellings) is driven above. Since 10.15 the certificate bag builders and the container builder
 * are driven too, over the shared fixed certificate/CRL DER: `PKCS12_SAFEBAG_create_cert`/`_crl`
 * and the four `get1_*` readers, `PKCS12_add_cert`, and `PKCS12_create(_ex/_ex2)` with the plain
 * `data` contentInfo and no MAC so the `PFX` bytes are comparable.
 *
 * The reader that closes the pair, `PKCS12_parse`, is driven too (10.17, whose last blocker
 * `ossl_x509_add_cert_new` 10.14.1 landed): a container is built by `PKCS12_create` from the
 * **fixed matching** `(key, certificate)` pair -- the certificate's own `test/certs/root-key.pem`
 * PKCS#8 DER and the shared `RT_X509_CERT_DER` -- with a second copy of the certificate in the
 * `ca` stack and a fixed-salt MAC, `i2d_PKCS12`'d, read back through `d2i_PKCS12`, and parsed.
 * The key's identity, the certificate and CA counts, each recovered certificate's serial and
 * re-encoded DER, and the wrong-password and NULL-container refusals with their error
 * coordinates are the observations (docs/PHASE-10-SUBPHASES.md sections 3.2, 3.5).
 *
 * Everything is borrowed or literal: the DER fixtures below are hand-written constants, the
 * strings are literals, and no pointer address is ever printed (two sides allocate differently).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include "rt_keyformat_keys.h"
#include "rt_x509_der.h"

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`.
 * --------------------------------------------------------------------------------------------- */

static void out_hex(const char *key, const unsigned char *p, long n)
{
    long i;

    if (p == NULL) {
        printf("%s=null\n", key);
        return;
    }
    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_ptr(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

/* The first error on the queue as `lib.reason`, then the queue is cleared. If an arm raises more
 * than one error, only the first is printed: the authority's `ERR_get_error` is LIFO, so the first
 * popped is the last raised, which is the coordinate a caller sees. */
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
 * Fixed DER fixtures.
 *
 * All are hand-written constants, so both sides decode the same input rather than one side's
 * output. The digest octets are a walking literal, not a real digest.
 * --------------------------------------------------------------------------------------------- */

/* PKCS8_PRIV_KEY_INFO ::= SEQUENCE { version 0, rsaEncryption+NULL, OCTET STRING {00} }. */
static const unsigned char FIX_PKCS8[] = {
    0x30, 0x15,
      0x02, 0x01, 0x00,
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00,
      0x04, 0x01, 0x00
};

/* X509_SIG (EncryptedPrivateKeyInfo) ::= SEQUENCE { rsaEncryption+NULL, OCTET STRING {ab cd} }.
 * The algorithm is deliberately not a PBE one: this probe never decrypts, it only carries the
 * bytes, so a well-formed but inert `AlgorithmIdentifier` keeps the fixture free of a cipher. */
static const unsigned char FIX_X509_SIG[] = {
    0x30, 0x13,
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00,
      0x04, 0x02, 0xab, 0xcd
};

/* PKCS12_MAC_DATA ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER }.
 * DigestInfo = SEQUENCE { sha256+NULL, OCTET STRING of 32 bytes of 0x11 }. */
static const unsigned char FIX_MACDATA[] = {
    0x30, 0x41,
      0x30, 0x31,
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
          0x05, 0x00,
        0x04, 0x20,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x02, 0x02, 0x08, 0x00
};

/* PKCS12_BAGS ::= SEQUENCE { pkcs7-data, [0] EXPLICIT OCTET STRING {01 02 03} }. */
static const unsigned char FIX_BAGS[] = {
    0x30, 0x12,
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
      0xa0, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03
};

/* A SafeBag whose type is `safeContentsBag` (1.2.840.113549.1.12.10.1.6) and whose value is an
 * empty SEQUENCE OF SafeBag, which is the one ADB arm that is neither a pointer-union member nor
 * a certificate type. */
static const unsigned char FIX_SAFES[] = {
    0x30, 0x11,
      0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x06,
      0xa0, 0x02, 0x30, 0x00
};

/* The PKCS#8 `PrivateKeyInfo` of the fixed certificate's own key: `test/certs/root-key.pem`'s
 * DER, the private half of `RT_X509_CERT_DER`'s public key. It is a fixed constant so
 * `PKCS12_create` accepts the `(key, cert)` pair and `PKCS12_parse` can split a *matching*
 * certificate into `*cert` -- an arm a mismatched pair could not drive, because
 * `PKCS12_create` refuses one (`X509_check_private_key`). Both sides read the same bytes. */
static const unsigned char FIX_CERT_KEY[] = {
    0x30, 0x82, 0x04, 0xbe, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
    0x04, 0xa8, 0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
    0x01, 0x00, 0xe1, 0xe6, 0x00, 0xf5, 0x06, 0xbc, 0xa0, 0x46, 0x38, 0x79,
    0x0f, 0x3f, 0x1e, 0x71, 0x19, 0x13, 0x6d, 0x02, 0xdf, 0x2b, 0x9b, 0x76,
    0x6b, 0xfc, 0xac, 0xb0, 0x21, 0xed, 0xd6, 0x91, 0x08, 0x42, 0x3b, 0xa5,
    0x63, 0x35, 0xec, 0x52, 0x5b, 0xa0, 0xa2, 0x4a, 0xc5, 0xd6, 0x00, 0x94,
    0x03, 0x97, 0x5a, 0x3d, 0xb9, 0x67, 0x28, 0xd2, 0x7d, 0xe3, 0x21, 0x5c,
    0xa4, 0xed, 0xc6, 0x3c, 0x8d, 0x8e, 0x84, 0xd1, 0x9d, 0x54, 0xc3, 0x3d,
    0xd9, 0x74, 0xa2, 0x96, 0x76, 0x67, 0x71, 0xf9, 0xc6, 0x1a, 0x50, 0x77,
    0xb3, 0xfd, 0x78, 0xee, 0x5b, 0xe0, 0xe3, 0x8c, 0x89, 0x23, 0xc2, 0x9a,
    0x22, 0xec, 0x3e, 0xd4, 0x37, 0x9e, 0x07, 0xcd, 0xc0, 0x2b, 0x55, 0x11,
    0x17, 0x3a, 0x34, 0x42, 0x1c, 0x69, 0x0d, 0x3a, 0x18, 0xb0, 0xed, 0x15,
    0x94, 0x5e, 0xc6, 0xfd, 0x9e, 0x87, 0xc6, 0x1c, 0xe7, 0x94, 0x1a, 0x92,
    0xc0, 0x5f, 0x05, 0xc1, 0x73, 0x43, 0xe5, 0x03, 0xde, 0x09, 0x91, 0xc9,
    0x24, 0xce, 0xd8, 0x8e, 0x8b, 0x7e, 0x2e, 0xe0, 0x31, 0x48, 0xd1, 0x86,
    0x2a, 0x6a, 0x55, 0x26, 0x7a, 0xe8, 0x0b, 0x36, 0x4e, 0x97, 0xb1, 0xe0,
    0xa4, 0xc9, 0xda, 0x5c, 0x69, 0x4b, 0x03, 0x80, 0x08, 0x56, 0x83, 0xa3,
    0x1f, 0xb2, 0x2a, 0xb8, 0xc1, 0x4c, 0xfe, 0xc5, 0xb1, 0x4d, 0xd4, 0xc0,
    0x01, 0xaa, 0xed, 0xbe, 0xce, 0x25, 0xbd, 0xee, 0x69, 0xad, 0xf6, 0x07,
    0xcd, 0x6e, 0x2b, 0xa1, 0x89, 0x54, 0xf5, 0x68, 0xeb, 0x98, 0x09, 0xed,
    0xc9, 0x60, 0x66, 0xcb, 0x33, 0x62, 0x4a, 0x03, 0xb0, 0x68, 0xd6, 0x0e,
    0xab, 0x5f, 0xc1, 0x35, 0x55, 0x7e, 0xfd, 0x46, 0xee, 0xba, 0xeb, 0xdc,
    0xb6, 0xa2, 0xa3, 0xed, 0x85, 0x7f, 0x77, 0xdf, 0xb5, 0x68, 0x22, 0x43,
    0x7e, 0x66, 0x24, 0x23, 0xaf, 0xc5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
    0x82, 0x01, 0x01, 0x00, 0x95, 0x9f, 0x52, 0x62, 0xf8, 0xe3, 0x57, 0x05,
    0x2b, 0xc2, 0x83, 0x66, 0xbb, 0x33, 0x0d, 0xf8, 0xdf, 0xeb, 0x57, 0x05,
    0xfb, 0x22, 0xa4, 0xc3, 0xe7, 0x5d, 0x82, 0x1b, 0x96, 0x52, 0xd9, 0xb5,
    0x84, 0xec, 0x36, 0x9a, 0x30, 0xbd, 0x1c, 0x13, 0x79, 0x6b, 0x2d, 0x3e,
    0x61, 0x83, 0xa8, 0x1d, 0x47, 0x98, 0x3a, 0x85, 0x29, 0x74, 0xc2, 0x0c,
    0xfe, 0xbb, 0xee, 0x41, 0xcf, 0x5b, 0xac, 0x27, 0x09, 0xb2, 0x0d, 0x13,
    0x67, 0x7e, 0x3f, 0xda, 0x11, 0x16, 0xb7, 0xb6, 0x2c, 0xb7, 0xd3, 0x8e,
    0xfa, 0x5d, 0x4e, 0xca, 0x44, 0x9f, 0x1c, 0x1c, 0x08, 0x9b, 0xbc, 0xfa,
    0x02, 0x9b, 0x35, 0x26, 0x65, 0x37, 0x0a, 0xdf, 0x91, 0x2b, 0xa6, 0x6d,
    0x0d, 0x1b, 0x14, 0xd7, 0x68, 0x65, 0xa1, 0x8b, 0xb3, 0x47, 0x17, 0xb3,
    0x98, 0x55, 0x02, 0xc1, 0x03, 0xec, 0x58, 0x64, 0x75, 0xc4, 0x0f, 0x5d,
    0xba, 0xc4, 0x07, 0x19, 0xb8, 0x4c, 0xe8, 0x5d, 0x16, 0x5c, 0x58, 0x93,
    0x52, 0xe9, 0x70, 0x7f, 0x9c, 0x7f, 0xd3, 0xa7, 0xa0, 0x3b, 0x82, 0x1c,
    0x0d, 0x02, 0xff, 0xaa, 0x2e, 0x41, 0xef, 0xd0, 0x72, 0xa2, 0xef, 0x98,
    0x9c, 0x44, 0x17, 0x72, 0xf5, 0xa5, 0x17, 0xee, 0xac, 0x84, 0xf6, 0xfa,
    0x76, 0xf4, 0x1b, 0x1e, 0xe3, 0x51, 0x59, 0xde, 0xd0, 0x25, 0x15, 0x3f,
    0x9c, 0x9f, 0xf2, 0x85, 0x40, 0xd0, 0xf0, 0xac, 0x7c, 0x7b, 0x55, 0x81,
    0xd9, 0x02, 0x5e, 0x98, 0x16, 0xdf, 0xde, 0x3c, 0xe4, 0xac, 0x6c, 0x47,
    0xc5, 0x6a, 0x23, 0x72, 0xbe, 0x9a, 0xbc, 0x93, 0x90, 0xb8, 0xd9, 0x38,
    0x0c, 0x2a, 0x3e, 0x92, 0xc5, 0x1c, 0xa6, 0x22, 0x6a, 0x28, 0xb1, 0x76,
    0xe9, 0xd1, 0xb2, 0x2d, 0x3c, 0xa9, 0xa8, 0xbd, 0xec, 0xd4, 0xbe, 0x85,
    0x5d, 0xb4, 0x36, 0x92, 0xf9, 0x46, 0xa8, 0xc1, 0x02, 0x81, 0x81, 0x00,
    0xf8, 0x1a, 0x6f, 0xfa, 0xe2, 0x40, 0x66, 0x4e, 0xcd, 0xf3, 0x7f, 0x8d,
    0xf4, 0x34, 0xac, 0x0e, 0x6c, 0xd0, 0xd4, 0x8d, 0x69, 0xa7, 0xdb, 0x67,
    0xc0, 0x7b, 0xc7, 0x92, 0x8d, 0xe0, 0x69, 0x60, 0x6b, 0xd8, 0xed, 0x1b,
    0x0b, 0xb9, 0x25, 0xd8, 0x2c, 0x8b, 0x95, 0x46, 0x7c, 0x16, 0x2d, 0x52,
    0xba, 0x26, 0x4f, 0x91, 0x60, 0x57, 0x6d, 0xf7, 0xd9, 0x6c, 0xbc, 0x5b,
    0x1f, 0xbb, 0x7c, 0xa6, 0x9b, 0xec, 0xbe, 0x75, 0x42, 0xe3, 0xe0, 0x56,
    0x91, 0xd9, 0x90, 0x47, 0xd7, 0x6e, 0xea, 0x6b, 0x65, 0xd7, 0xa1, 0xa8,
    0x8d, 0x9c, 0x4f, 0x13, 0x51, 0x8b, 0xd0, 0x6a, 0xaa, 0xc3, 0xc0, 0xb2,
    0x24, 0x64, 0x80, 0x4c, 0x19, 0xbd, 0x50, 0x9b, 0x3f, 0xae, 0x8a, 0xb5,
    0x85, 0x0c, 0x67, 0xbd, 0x6a, 0xdb, 0x19, 0x9a, 0x76, 0xf8, 0xf1, 0x89,
    0x4e, 0x77, 0x65, 0x6f, 0xe5, 0x29, 0x21, 0x73, 0x02, 0x81, 0x81, 0x00,
    0xe9, 0x16, 0xa3, 0xd1, 0xb1, 0xda, 0xe0, 0xbc, 0xdb, 0xd8, 0x22, 0xf1,
    0x7f, 0x97, 0xa8, 0xea, 0x9e, 0x22, 0x04, 0xd6, 0x9c, 0x0f, 0x76, 0xac,
    0x0a, 0x89, 0x09, 0x98, 0x31, 0x13, 0x20, 0x0c, 0x17, 0x16, 0x98, 0xe7,
    0x1c, 0xb0, 0xc4, 0xba, 0xaf, 0x16, 0xdb, 0xa3, 0x80, 0x08, 0x2b, 0xfa,
    0xbd, 0x9b, 0x47, 0x79, 0xf8, 0x6d, 0x3b, 0x45, 0x0b, 0xa8, 0x90, 0xb5,
    0xa5, 0x12, 0xc5, 0xe7, 0xfd, 0xe5, 0xc6, 0x1a, 0x76, 0xd7, 0xda, 0x69,
    0xe5, 0x0d, 0x5b, 0x48, 0x8c, 0xac, 0x38, 0xa5, 0x09, 0xb5, 0x9c, 0xaa,
    0x37, 0x0b, 0xe1, 0xbd, 0x13, 0xa8, 0x88, 0x58, 0x13, 0x0d, 0x1c, 0x9f,
    0xbb, 0x8f, 0x1e, 0x2a, 0xc0, 0x31, 0xd7, 0xca, 0x73, 0x44, 0x9f, 0xd9,
    0x14, 0x7b, 0x07, 0xa8, 0xd6, 0xcd, 0x51, 0x55, 0xa3, 0x17, 0x63, 0x5f,
    0xd7, 0x23, 0x42, 0xe8, 0xf1, 0x2b, 0x3b, 0xe7, 0x02, 0x81, 0x81, 0x00,
    0xb9, 0xf2, 0x26, 0x87, 0x23, 0xd7, 0x1c, 0x56, 0x67, 0xa8, 0xdd, 0xaa,
    0xa8, 0xa2, 0x69, 0x69, 0x8e, 0x48, 0x9d, 0x65, 0x37, 0x10, 0xa5, 0x32,
    0x07, 0x63, 0x3d, 0xda, 0x2b, 0x17, 0x4c, 0x23, 0x05, 0xf1, 0x59, 0x13,
    0x72, 0x1f, 0xdb, 0xab, 0x3f, 0x07, 0x86, 0x63, 0x83, 0x50, 0xa3, 0xbb,
    0x62, 0xe4, 0x9f, 0xb1, 0xd7, 0x40, 0xef, 0x9c, 0x58, 0x8a, 0x54, 0x48,
    0xff, 0x69, 0x67, 0x2c, 0xff, 0xa3, 0xd9, 0xc2, 0xcc, 0xd5, 0x39, 0x27,
    0xe8, 0xbb, 0xe4, 0x94, 0xd3, 0x73, 0xbf, 0xa1, 0xaa, 0x7c, 0x88, 0x1e,
    0x69, 0xb4, 0x02, 0xd7, 0xf9, 0xc0, 0x0d, 0xfe, 0x43, 0xe9, 0xde, 0x9c,
    0x25, 0x06, 0x65, 0xd9, 0xa3, 0x58, 0xed, 0xf6, 0xcd, 0x2d, 0xa5, 0xac,
    0x12, 0x01, 0x90, 0x26, 0xb8, 0xd5, 0x69, 0x45, 0x09, 0x71, 0xde, 0xa5,
    0x07, 0xf8, 0x18, 0x40, 0x5a, 0xc2, 0x0e, 0xdd, 0x02, 0x81, 0x80, 0x1b,
    0xeb, 0x54, 0x50, 0x07, 0xc7, 0xb9, 0xe7, 0xa5, 0x45, 0xac, 0x59, 0xd4,
    0xf8, 0xab, 0x88, 0xfe, 0xcc, 0x00, 0x5c, 0x5c, 0x71, 0x15, 0xbb, 0xe1,
    0xbf, 0x2c, 0x61, 0x08, 0x6f, 0xcc, 0x04, 0xe6, 0xb7, 0x14, 0x35, 0x8a,
    0xa0, 0x39, 0xd0, 0x4a, 0xac, 0xa8, 0x3e, 0x5b, 0x55, 0x9f, 0x3e, 0xf7,
    0x7b, 0x24, 0x02, 0x9e, 0x19, 0x27, 0x62, 0x4b, 0xd5, 0x33, 0x10, 0x2e,
    0xe7, 0xa2, 0xc0, 0xf9, 0x0e, 0x8e, 0xbe, 0x18, 0xc2, 0x1e, 0x2d, 0x54,
    0xfc, 0x56, 0x94, 0xc8, 0x14, 0xd0, 0xec, 0x23, 0xcf, 0x97, 0x26, 0x64,
    0x55, 0x8e, 0x02, 0x81, 0xda, 0x4c, 0x0a, 0x90, 0xad, 0x9f, 0x62, 0x1a,
    0xab, 0x37, 0xe7, 0xd3, 0x01, 0xa5, 0x61, 0x60, 0x91, 0x35, 0xbc, 0x60,
    0xd1, 0xa3, 0xc7, 0x3b, 0x83, 0x78, 0x5c, 0x93, 0x9e, 0x77, 0x8e, 0xc1,
    0x4c, 0x3d, 0xf5, 0x7c, 0xfd, 0xba, 0xbd, 0x02, 0x81, 0x80, 0x35, 0x97,
    0x37, 0x3e, 0x61, 0x7b, 0xda, 0x4b, 0x61, 0x80, 0xe2, 0x17, 0x81, 0x77,
    0x8d, 0xd8, 0xdb, 0x1b, 0xf4, 0x02, 0x98, 0xee, 0x35, 0x54, 0x17, 0x5f,
    0x77, 0xcd, 0x69, 0x15, 0xa8, 0xc9, 0x2a, 0x6e, 0x13, 0x6a, 0xc9, 0x2e,
    0x30, 0xb4, 0xda, 0x59, 0xae, 0x75, 0x28, 0x77, 0x28, 0x5b, 0xe7, 0x5d,
    0x41, 0x02, 0xf2, 0xef, 0x6a, 0xad, 0x5c, 0x7e, 0x77, 0x5f, 0x84, 0x8b,
    0x94, 0xef, 0xd1, 0x69, 0xc5, 0x7d, 0x85, 0x1a, 0x12, 0x5f, 0x93, 0x6a,
    0xee, 0x2b, 0xd2, 0x3b, 0xcb, 0x0c, 0xd5, 0xf9, 0xd4, 0xe7, 0x99, 0x01,
    0xad, 0xef, 0x95, 0xfd, 0x98, 0x0a, 0x90, 0x6e, 0x17, 0x7b, 0xae, 0xbd,
    0x3f, 0x51, 0xdd, 0xe1, 0x3a, 0x66, 0x9a, 0x9a, 0x18, 0x0e, 0x18, 0x0e,
    0x26, 0xaf, 0xba, 0xa0, 0x8e, 0x0b, 0xf3, 0xbb, 0xa8, 0x22, 0x8c, 0xaa,
    0xbe, 0x5b, 0x51, 0x2b, 0x78, 0x4c,
};

/* ---------------------------------------------------------------------------------------------
 * Item identity and the four Unicode conversions.
 * --------------------------------------------------------------------------------------------- */

static void court_items(void)
{
    out_ptr("it.macdata", (const void *)PKCS12_MAC_DATA_it());
    out_ptr("it.bags", (const void *)PKCS12_BAGS_it());
    out_ptr("it.safebag", (const void *)PKCS12_SAFEBAG_it());
    out_ptr("it.safebags", (const void *)PKCS12_SAFEBAGS_it());
    out_int("it.safebag_stable", PKCS12_SAFEBAG_it() == PKCS12_SAFEBAG_it());
    out_int("it.macdata_stable", PKCS12_MAC_DATA_it() == PKCS12_MAC_DATA_it());
    out_int("it.bags_stable", PKCS12_BAGS_it() == PKCS12_BAGS_it());
    out_int("it.safebags_stable", PKCS12_SAFEBAGS_it() == PKCS12_SAFEBAGS_it());
}

static void court_unicode(void)
{
    unsigned char *uni = NULL;
    int unilen = 0;
    unsigned char *r;
    const unsigned char astral[] = { 'a', 0xf0, 0x9f, 0x98, 0x80, 'b', 0x00 };
    unsigned char utf16bad[3] = { 0x00, 'a', 0x00 };

    /* The naive pair over a fixed ASCII string. */
    r = OPENSSL_asc2uni("hello", -1, &uni, &unilen);
    out_ptr("uni.asc2uni", r);
    out_hex("uni.asc2uni.hex", r, unilen);
    out_int("uni.asc2uni.len", unilen);
    if (r != NULL) {
        char *back = OPENSSL_uni2asc(r, unilen);
        out_hex("uni.uni2asc.hex", (const unsigned char *)back,
                back != NULL ? (long)strlen(back) : 0);
        OPENSSL_free(back);
    }

    /* The UTF-8 pair, including an astral code point that forces a surrogate pair. */
    r = OPENSSL_utf82uni((const char *)astral, 6, &uni, &unilen);
    out_ptr("uni.utf82uni", r);
    out_hex("uni.utf82uni.hex", r, unilen);
    out_int("uni.utf82uni.len", unilen);
    if (r != NULL) {
        char *back = OPENSSL_uni2utf8(r, unilen);
        out_hex("uni.uni2utf8.hex", (const unsigned char *)back,
                back != NULL ? (long)strlen(back) : 0);
        OPENSSL_free(back);
        OPENSSL_free(r);
    }

    /* The guards: a negative ASCII length and an odd UTF-16 length both answer NULL. */
    out_ptr("uni.asc2uni.neg", OPENSSL_asc2uni("x", -2, &uni, &unilen));
    out_ptr("uni.uni2asc.odd", OPENSSL_uni2asc(utf16bad, 3));
    out_ptr("uni.uni2utf8.odd", OPENSSL_uni2utf8(utf16bad, 3));
}

/* ---------------------------------------------------------------------------------------------
 * The `PKCS12_SAFEBAG` item: DER bytes, the accessor surface and the attribute set.
 * --------------------------------------------------------------------------------------------- */

static void court_safebag(void)
{
    static const unsigned char secret_val[3] = { 0x01, 0x02, 0x03 };
    static unsigned char keyid[4] = { 0x04, 0x05, 0x06, 0x07 };
    PKCS12_SAFEBAG *bag;
    unsigned char *der = NULL, *der2 = NULL, *der3 = NULL;
    long len, len2, len3;
    char *friendly;

    /* The plain allocator, so this name is driven directly rather than only through the
     * constructors that call it. */
    bag = PKCS12_SAFEBAG_new();
    out_ptr("safebag.new", bag);
    PKCS12_SAFEBAG_free(bag);

    bag = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 3);
    out_ptr("safebag.secret", bag);
    if (bag == NULL)
        return;
    out_int("safebag.get_nid", PKCS12_SAFEBAG_get_nid(bag));
    out_int("safebag.get_bag_nid", PKCS12_SAFEBAG_get_bag_nid(bag));
    out_int("safebag.type_nid", OBJ_obj2nid(PKCS12_SAFEBAG_get0_type(bag)));
    out_int("safebag.bagtype_nid", OBJ_obj2nid(PKCS12_SAFEBAG_get0_bag_type(bag)));
    out_ptr("safebag.bag_obj", PKCS12_SAFEBAG_get0_bag_obj(bag));
    out_ptr("safebag.p8inf", PKCS12_SAFEBAG_get0_p8inf(bag));
    out_ptr("safebag.pkcs8", PKCS12_SAFEBAG_get0_pkcs8(bag));
    out_ptr("safebag.safes", PKCS12_SAFEBAG_get0_safes(bag));
    out_ptr("safebag.attrs_empty", PKCS12_SAFEBAG_get0_attrs(bag));

    len = i2d_PKCS12_SAFEBAG(bag, &der);
    out_hex("safebag.secret.der", der, len);

    /* The decoder reads the encoder's bytes back, and re-encoding them is the same document. */
    {
        const unsigned char *p = der;
        PKCS12_SAFEBAG *rt = d2i_PKCS12_SAFEBAG(NULL, &p, len);

        out_ptr("safebag.d2i", rt);
        if (rt != NULL) {
            out_int("safebag.d2i.get_nid", PKCS12_SAFEBAG_get_nid(rt));
            out_int("safebag.d2i.get_bag_nid", PKCS12_SAFEBAG_get_bag_nid(rt));
            len2 = i2d_PKCS12_SAFEBAG(rt, &der2);
            out_hex("safebag.d2i.der", der2, len2);
            PKCS12_SAFEBAG_free(rt);
        }
    }

    /* The attribute set: the friendlyname first, then the local key id, so the DER's SET OF
     * ordering is driven rather than assumed. */
    out_int("safebag.friendly_add", PKCS12_add_friendlyname_asc(bag, "probe", -1));
    len3 = i2d_PKCS12_SAFEBAG(bag, &der3);
    out_hex("safebag.friendly.der", der3, len3);
    OPENSSL_free(der3);

    out_int("safebag.keyid_add", PKCS12_add_localkeyid(bag, keyid, 4));
    der3 = NULL;
    len3 = i2d_PKCS12_SAFEBAG(bag, &der3);
    out_hex("safebag.attrs.der", der3, len3);

    out_int("safebag.attrs_count", X509at_get_attr_count(PKCS12_SAFEBAG_get0_attrs(bag)));
    out_ptr("safebag.attr_friendly", PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName));
    out_ptr("safebag.attr_local", PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID));
    out_ptr("safebag.get_attr_friendly", PKCS12_get_attr(bag, NID_friendlyName));
    out_ptr("safebag.get_attr_gen_friendly",
            PKCS12_get_attr_gen(PKCS12_SAFEBAG_get0_attrs(bag), NID_friendlyName));

    friendly = PKCS12_get_friendlyname(bag);
    out_hex("safebag.friendlyname", (const unsigned char *)friendly,
            friendly != NULL ? (long)strlen(friendly) : 0);
    OPENSSL_free(friendly);

    /* set0_attrs releases the old stack and adopts the new one; NULL is the observable arm. */
    PKCS12_SAFEBAG_set0_attrs(bag, NULL);
    out_ptr("safebag.attrs_after_set0", PKCS12_SAFEBAG_get0_attrs(bag));

    OPENSSL_free(der);
    OPENSSL_free(der2);
    OPENSSL_free(der3);
    PKCS12_SAFEBAG_free(bag);
}

/* The four remaining attribute writers, each on its own fresh bag so no duplicate guard fires. */
static void court_attr_writers(void)
{
    static const unsigned char secret_val[1] = { 0x2a };
    static unsigned char keyid[2] = { 0xaa, 0xbb };
    static const unsigned char bmp[4] = { 0x00, 'h', 0x00, 'i' };
    PKCS12_SAFEBAG *a, *b, *c, *d;

    a = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.by_nid", PKCS12_add1_attr_by_NID(a, NID_localKeyID, V_ASN1_OCTET_STRING, keyid, 2));
    PKCS12_SAFEBAG_free(a);

    b = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.by_txt", PKCS12_add1_attr_by_txt(b, "friendlyName", MBSTRING_ASC,
                                                   (const unsigned char *)"x", 1));
    PKCS12_SAFEBAG_free(b);

    c = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.friendly_uni", PKCS12_add_friendlyname_uni(c, bmp, 4));
    PKCS12_SAFEBAG_free(c);

    c = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.friendly_utf8", PKCS12_add_friendlyname_utf8(c, "z", -1));
    PKCS12_SAFEBAG_free(c);

    d = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.csp", PKCS12_add_CSPName_asc(d, "csp", -1));
    PKCS12_SAFEBAG_free(d);
}

/* ---------------------------------------------------------------------------------------------
 * The key-bag and shrouded-key-bag constructors: ownership by pointer identity, and the PKCS#8
 * attribute writer.
 * --------------------------------------------------------------------------------------------- */

static void court_keybags(void)
{
    const unsigned char *p;
    PKCS8_PRIV_KEY_INFO *p8;
    X509_SIG *sig;
    PKCS12_SAFEBAG *kb, *sb;
    unsigned char *kd = NULL, *kd2 = NULL, *sd = NULL;
    long kl, kl2, sl;

    p = FIX_PKCS8;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    out_ptr("p8.d2i", p8);
    if (p8 == NULL)
        return;
    kb = PKCS12_SAFEBAG_create0_p8inf(p8);
    out_ptr("keybag", kb);
    if (kb == NULL)
        return;
    out_int("keybag.get_nid", PKCS12_SAFEBAG_get_nid(kb));
    out_int("keybag.p8inf_eq", PKCS12_SAFEBAG_get0_p8inf(kb) == p8);
    out_ptr("keybag.pkcs8", PKCS12_SAFEBAG_get0_pkcs8(kb));
    kl = i2d_PKCS12_SAFEBAG(kb, &kd);
    out_hex("keybag.der", kd, kl);

    /* The key-usage attribute lands on the PKCS#8 structure and shows up in the bag's bytes. */
    out_int("keybag.keyusage_add", PKCS8_add_keyusage(p8, 0x80));
    out_ptr("keybag.keyusage_get", PKCS8_get_attr(p8, NID_key_usage));
    kl2 = i2d_PKCS12_SAFEBAG(kb, &kd2);
    out_hex("keybag.keyusage.der", kd2, kl2);

    p = FIX_X509_SIG;
    sig = d2i_X509_SIG(NULL, &p, (long)sizeof(FIX_X509_SIG));
    out_ptr("sig.d2i", sig);
    if (sig == NULL)
        return;
    sb = PKCS12_SAFEBAG_create0_pkcs8(sig);
    out_ptr("shrouded", sb);
    if (sb == NULL)
        return;
    out_int("shrouded.get_nid", PKCS12_SAFEBAG_get_nid(sb));
    out_int("shrouded.pkcs8_eq", PKCS12_SAFEBAG_get0_pkcs8(sb) == sig);
    out_ptr("shrouded.p8inf", PKCS12_SAFEBAG_get0_p8inf(sb));
    sl = i2d_PKCS12_SAFEBAG(sb, &sd);
    out_hex("shrouded.der", sd, sl);

    PKCS12_SAFEBAG_free(sb);
    PKCS12_SAFEBAG_free(kb);
    OPENSSL_free(kd);
    OPENSSL_free(kd2);
    OPENSSL_free(sd);
}

/* ---------------------------------------------------------------------------------------------
 * PKCS12_BAGS, PKCS12_MAC_DATA and the safeContentsBag arm.
 * --------------------------------------------------------------------------------------------- */

static void court_items_roundtrip(void)
{
    const unsigned char *p;
    PKCS12_BAGS *b, *bn;
    PKCS12_MAC_DATA *md, *mn;
    PKCS12_SAFEBAG *sc;
    unsigned char *out = NULL;
    long len;

    p = FIX_BAGS;
    b = d2i_PKCS12_BAGS(NULL, &p, (long)sizeof(FIX_BAGS));
    out_ptr("bags.d2i", b);
    if (b != NULL) {
        len = i2d_PKCS12_BAGS(b, &out);
        out_hex("bags.der", out, len);
        OPENSSL_free(out);
    }
    bn = PKCS12_BAGS_new();
    out_ptr("bags.new", bn);
    PKCS12_BAGS_free(bn);
    PKCS12_BAGS_free(b);

    p = FIX_MACDATA;
    md = d2i_PKCS12_MAC_DATA(NULL, &p, (long)sizeof(FIX_MACDATA));
    out_ptr("macdata.d2i", md);
    if (md != NULL) {
        out = NULL;
        len = i2d_PKCS12_MAC_DATA(md, &out);
        out_hex("macdata.der", out, len);
        OPENSSL_free(out);
    }
    mn = PKCS12_MAC_DATA_new();
    out_ptr("macdata.new", mn);
    PKCS12_MAC_DATA_free(mn);
    PKCS12_MAC_DATA_free(NULL);
    PKCS12_MAC_DATA_free(md);

    p = FIX_SAFES;
    sc = d2i_PKCS12_SAFEBAG(NULL, &p, (long)sizeof(FIX_SAFES));
    out_ptr("safes.d2i", sc);
    if (sc != NULL) {
        out_int("safes.get_nid", PKCS12_SAFEBAG_get_nid(sc));
        out_int("safes.get_bag_nid", PKCS12_SAFEBAG_get_bag_nid(sc));
        out_ptr("safes.get0_safes", PKCS12_SAFEBAG_get0_safes(sc));
        out_ptr("safes.get0_bag_type", PKCS12_SAFEBAG_get0_bag_type(sc));
        out_ptr("safes.get0_bag_obj", PKCS12_SAFEBAG_get0_bag_obj(sc));
        out = NULL;
        len = i2d_PKCS12_SAFEBAG(sc, &out);
        out_hex("safes.der", out, len);
        OPENSSL_free(out);
        PKCS12_SAFEBAG_free(sc);
    }
}

/* ---------------------------------------------------------------------------------------------
 * 10.3: the `SafeBag` packer, the shrouded-key reader and the `add_*` surface.
 * --------------------------------------------------------------------------------------------- */

static void court_add3(void)
{
    static const unsigned char secret_val[3] = { 0x01, 0x02, 0x03 };
    const unsigned char *p;
    PKCS8_PRIV_KEY_INFO *p8;
    X509_SIG *sig;
    PKCS12_SAFEBAG *packed, *shrouded, *secret;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    unsigned char *der = NULL;
    long len;

    /* `PKCS12_item_pack_safebag`: pack a fixed PKCS#8 through `PKCS8_PRIV_KEY_INFO_it` as a
     * `certBag` whose value type is `x509Certificate`. The item is the caller's, so the packed
     * bytes are a function of the fixed input alone and are printed rather than parsed. */
    p = FIX_PKCS8;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    out_ptr("pack.p8", p8);
    if (p8 != NULL) {
        packed = PKCS12_item_pack_safebag(p8, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO),
                                          NID_x509Certificate, NID_certBag);
        out_ptr("pack.bag", packed);
        if (packed != NULL) {
            out_int("pack.get_nid", PKCS12_SAFEBAG_get_nid(packed));
            out_int("pack.bag_nid", PKCS12_SAFEBAG_get_bag_nid(packed));
            out_ptr("pack.bag_obj", PKCS12_SAFEBAG_get0_bag_obj(packed));
            len = i2d_PKCS12_SAFEBAG(packed, &der);
            out_hex("pack.der", der, len);
            OPENSSL_free(der);
            der = NULL;
            PKCS12_SAFEBAG_free(packed);
        }
        PKCS8_PRIV_KEY_INFO_free(p8);
    }

    /* `PKCS12_decrypt_skey(_ex)`: a shrouded key bag whose algorithm is not a PBE one. The reader
     * borrows the bag's `X509_SIG` and refuses with the error queue, which is the observable arm
     * this slice can drive without 10.4's `PKCS8_encrypt` to build a real ciphertext. The bag
     * adopts `sig`, so it is not freed here. */
    p = FIX_X509_SIG;
    sig = d2i_X509_SIG(NULL, &p, (long)sizeof(FIX_X509_SIG));
    out_ptr("skey.sig", sig);
    if (sig != NULL) {
        shrouded = PKCS12_SAFEBAG_create0_pkcs8(sig);
        out_ptr("skey.bag", shrouded);
        if (shrouded != NULL) {
            ERR_clear_error();
            out_ptr("skey.decrypt", PKCS12_decrypt_skey(shrouded, "password", -1));
            out_err("skey.decrypt.err");
            ERR_clear_error();
            out_ptr("skey.decrypt_ex",
                    PKCS12_decrypt_skey_ex(shrouded, "password", -1, NULL, NULL));
            out_err("skey.decrypt_ex.err");
            PKCS12_SAFEBAG_free(shrouded);
        }
    }

    /* `PKCS12_add_secret`: the `add_*` surface. A NULL `*pbags` is filled by the call itself,
     * and the appended bag is the returned pointer, so the DER is printed for fixed octets. */
    secret = PKCS12_add_secret(&bags, NID_pkcs7_data, secret_val, 3);
    out_ptr("add_secret.bag", secret);
    out_int("add_secret.num", sk_PKCS12_SAFEBAG_num(bags));
    if (secret != NULL) {
        out_int("add_secret.get_nid", PKCS12_SAFEBAG_get_nid(secret));
        out_int("add_secret.bag_nid", PKCS12_SAFEBAG_get_bag_nid(secret));
        len = i2d_PKCS12_SAFEBAG(secret, &der);
        out_hex("add_secret.der", der, len);
        OPENSSL_free(der);
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
}

/* ---------------------------------------------------------------------------------------------
 * The `PKCS12` container: the `PFX` bytes, the `MacData` fields and the authsafes' ordering.
 *
 * The `PKCS7` object's arms this lands were pulled forward from Phase 12 (see `src/pkcs7/`), so
 * the container's own DER is now comparable byte for byte: `i2d_PKCS12` prints the `PFX` order
 * (`version`, `authsafes`, `mac`), the `MacData`'s `digestAlgorithm`/`salt`/`iterations` are read
 * back through `PKCS12_get0_mac`, and a two-element `STACK_OF(PKCS7)` shows the authsafes'
 * `SEQUENCE OF` ordering. Everything is fixed input; no pointer address is printed.
 * --------------------------------------------------------------------------------------------- */

/* Build a one-`secretBag` `STACK_OF(PKCS12_SAFEBAG)` from a fixed octet string. */
static STACK_OF(PKCS12_SAFEBAG) *make_bags(const unsigned char *val, int len)
{
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;

    if (PKCS12_add_secret(&bags, NID_pkcs7_data, val, len) == NULL) {
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        return NULL;
    }
    return bags;
}

static void court_container(void)
{
    static const unsigned char secret_a[3] = { 0x01, 0x02, 0x03 };
    static const unsigned char secret_b[2] = { 0x09, 0x08 };
    static unsigned char maccsalt[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const unsigned char *p;
    PKCS12 *p12, *rt;
    PKCS7 *p7a, *p7b;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    STACK_OF(PKCS7) *safes, *back;
    unsigned char *der = NULL;
    long len;
    const ASN1_OCTET_STRING *mac = NULL, *msalt = NULL;
    const X509_ALGOR *malg = NULL;
    const ASN1_INTEGER *miter = NULL;
    BIO *bio;
    FILE *fp;
    int i;

    /* The two item accessors the container's template names, driven directly. */
    out_ptr("container.it", (const void *)PKCS12_it());
    out_int("container.it_stable", PKCS12_it() == PKCS12_it());
    out_ptr("container.it_authsafes", (const void *)PKCS12_AUTHSAFES_it());
    out_int("container.it_authsafes_stable", PKCS12_AUTHSAFES_it() == PKCS12_AUTHSAFES_it());

    /* `PKCS12_init`/`PKCS12_init_ex`: an empty `NID_pkcs7_data` container, its `PFX` bytes and
     * its accessors. */
    p12 = PKCS12_init(NID_pkcs7_data);
    out_ptr("init.data", p12);
    if (p12 != NULL) {
        out_int("init.mac_present", PKCS12_mac_present(p12));
        len = i2d_PKCS12(p12, &der);
        out_int("init.der.len", len);
        out_hex("init.der", der, len);
        OPENSSL_free(der);
        der = NULL;
        PKCS12_free(p12);
    }
    p12 = PKCS12_init_ex(NID_pkcs7_data, NULL, NULL);
    out_ptr("init_ex.data", p12);
    if (p12 != NULL) {
        der = NULL;
        out_int("init_ex.der.len", i2d_PKCS12(p12, &der));
        OPENSSL_free(der);
        der = NULL;
        PKCS12_free(p12);
    }

    /* The `default:` arm of `PKCS12_init_ex`'s mode switch, with its coordinate. */
    ERR_clear_error();
    out_ptr("init.badmode", PKCS12_init(NID_pkcs7_encrypted));
    out_err("init.badmode.err");

    /* `PKCS12_new`/`PKCS12_free`, including the NULL release. */
    p12 = PKCS12_new();
    out_ptr("new.p12", p12);
    PKCS12_free(p12);
    PKCS12_free(NULL);

    /* A two-element authsafes: two `NID_pkcs7_data` contentInfos over different secrets, packed
     * into one container. The DER's authsafes column is the `SEQUENCE OF PKCS7` in push order. */
    bags = make_bags(secret_a, 3);
    p7a = PKCS12_pack_p7data(bags);
    out_ptr("p7data.a", p7a);
    safes = sk_PKCS7_new_null();
    if (p7a != NULL)
        sk_PKCS7_push(safes, p7a);
    bags = make_bags(secret_b, 2);
    p7b = PKCS12_pack_p7data(bags);
    out_ptr("p7data.b", p7b);
    if (p7b != NULL)
        sk_PKCS7_push(safes, p7b);
    out_int("safes.num", sk_PKCS7_num(safes));

    p12 = PKCS12_init(NID_pkcs7_data);
    bags = make_bags(secret_a, 3);
    p7a = PKCS12_pack_p7data(bags);
    out_int("pack_authsafes.ret", PKCS12_pack_authsafes(p12, safes));
    der = NULL;
    len = i2d_PKCS12(p12, &der);
    out_hex("authsafes.der", der, len);

    /* `PKCS12_get0_mac` on a container with no `MacData` clears every slot. */
    mac = (const ASN1_OCTET_STRING *)0x1;
    msalt = (const ASN1_OCTET_STRING *)0x1;
    malg = (const X509_ALGOR *)0x1;
    miter = (const ASN1_INTEGER *)0x1;
    PKCS12_get0_mac(&mac, &malg, &msalt, &miter, p12);
    out_ptr("nomac.digest", mac);
    out_ptr("nomac.alg", malg);
    out_ptr("nomac.salt", msalt);
    out_ptr("nomac.iter", miter);

    /* `PKCS12_setup_mac` over a fixed salt and iteration count, then the `MacData` fields the
     * accessor answers and the `PFX` bytes that now carry them. */
    out_int("setup_mac.ret", PKCS12_setup_mac(p12, 0x0800, maccsalt, 8, EVP_sha256()));
    out_int("mac.present", PKCS12_mac_present(p12));
    PKCS12_get0_mac(&mac, &malg, &msalt, &miter, p12);
    out_int("mac.iter", ASN1_INTEGER_get(miter));
    out_int("mac.salt.len", ASN1_STRING_length(msalt));
    out_hex("mac.salt", ASN1_STRING_get0_data(msalt), ASN1_STRING_length(msalt));
    out_int("mac.alg.nid", malg != NULL ? OBJ_obj2nid(malg->algorithm) : -1);
    out_int("mac.digest.len", ASN1_STRING_length(mac));
    OPENSSL_free(der);
    der = NULL;
    len = i2d_PKCS12(p12, &der);
    out_int("mac.der.len", len);
    out_hex("mac.der", der, len);

    /* The decoder reads the encoder's bytes back; re-encoding them is the same document, which
     * is what makes the `PFX` order observable rather than asserted. */
    p = der;
    rt = d2i_PKCS12(NULL, &p, len);
    out_ptr("roundtrip.p12", rt);
    if (rt != NULL) {
        unsigned char *der2 = NULL;
        long len2 = i2d_PKCS12(rt, &der2);

        out_int("roundtrip.mac_present", PKCS12_mac_present(rt));
        PKCS12_get0_mac(&mac, &malg, &msalt, &miter, rt);
        out_int("roundtrip.mac.iter", ASN1_INTEGER_get(miter));
        out_hex("roundtrip.mac.salt", ASN1_STRING_get0_data(msalt),
                ASN1_STRING_length(msalt));
        out_hex("roundtrip.der", der2, len2);
        OPENSSL_free(der2);

        /* `PKCS12_unpack_authsafes`: the two inner contentInfos, in order, by type NID and by
         * the octet string each carries. */
        ERR_clear_error();
        back = PKCS12_unpack_authsafes(rt);
        out_ptr("unpack_authsafes", back);
        out_int("unpack_authsafes.num", back != NULL ? sk_PKCS7_num(back) : -1);
        if (back != NULL) {
            for (i = 0; i < sk_PKCS7_num(back); i++) {
                PKCS7 *in = sk_PKCS7_value(back, i);

                out_int("unpack_authsafes.type", OBJ_obj2nid(in->type));
                out_hex("unpack_authsafes.data", in->d.data->data, in->d.data->length);
            }
            sk_PKCS7_pop_free(back, PKCS7_free);
        }
        PKCS12_free(rt);
    }
    OPENSSL_free(der);
    der = NULL;

    /* `PKCS12_unpack_p7data` over a freshly packed contentInfo: the bags come back and their DER
     * is the one that went in. */
    {
        PKCS12_SAFEBAG *first;

        bags = make_bags(secret_a, 3);
        p7a = PKCS12_pack_p7data(bags);
        ERR_clear_error();
        back = PKCS12_unpack_p7data(p7a);
        out_ptr("unpack_p7data", back);
        out_int("unpack_p7data.num", back != NULL ? sk_PKCS12_SAFEBAG_num(back) : -1);
        if (back != NULL) {
            unsigned char *bd = NULL;
            long bl;

            first = sk_PKCS12_SAFEBAG_value(back, 0);
            bl = i2d_PKCS12_SAFEBAG(first, &bd);
            out_hex("unpack_p7data.bag.der", bd, bl);
            OPENSSL_free(bd);
            sk_PKCS12_SAFEBAG_pop_free(back, PKCS12_SAFEBAG_free);
        }
        PKCS7_free(p7a);
    }

    /* `PKCS12_add_safes(_ex)`: the same container built in one call, whose DER must be the one
     * `pack_authsafes` produced above. */
    safes = sk_PKCS7_new_null();
    bags = make_bags(secret_a, 3);
    p7a = PKCS12_pack_p7data(bags);
    if (p7a != NULL)
        sk_PKCS7_push(safes, p7a);
    bags = make_bags(secret_b, 2);
    p7b = PKCS12_pack_p7data(bags);
    if (p7b != NULL)
        sk_PKCS7_push(safes, p7b);
    p12 = PKCS12_add_safes(safes, NID_pkcs7_data);
    out_ptr("add_safes.p12", p12);
    if (p12 != NULL) {
        der = NULL;
        len = i2d_PKCS12(p12, &der);
        out_hex("add_safes.der", der, len);

        /* The BIO and `FILE` spellings over the same object. */
        bio = BIO_new(BIO_s_mem());
        out_int("i2d_bio.ret", i2d_PKCS12_bio(bio, p12));
        {
            char *contents = NULL;
            long n = BIO_get_mem_data(bio, &contents);

            out_hex("i2d_bio.der", (const unsigned char *)contents, n);
            {
                PKCS12 *frombio = d2i_PKCS12_bio(bio, NULL);

                out_ptr("d2i_bio.p12", frombio);
                if (frombio != NULL) {
                    unsigned char *bd = NULL;
                    long bl = i2d_PKCS12(frombio, &bd);
                    out_hex("d2i_bio.der", bd, bl);
                    OPENSSL_free(bd);
                    PKCS12_free(frombio);
                }
            }
        }
        BIO_free(bio);

        fp = tmpfile();
        if (fp != NULL) {
            PKCS12 *fromfp;

            out_int("i2d_fp.ret", i2d_PKCS12_fp(fp, p12));
            rewind(fp);
            ERR_clear_error();
            fromfp = d2i_PKCS12_fp(fp, NULL);
            out_ptr("d2i_fp.p12", fromfp);
            if (fromfp != NULL) {
                unsigned char *bd = NULL;
                long bl = i2d_PKCS12(fromfp, &bd);
                out_hex("d2i_fp.der", bd, bl);
                OPENSSL_free(bd);
                PKCS12_free(fromfp);
            }
            fclose(fp);
        }
        OPENSSL_free(der);
        der = NULL;
        PKCS12_free(p12);
    }

    /* The `_ex` spelling over the same stack: the same container, so the same bytes. */
    p12 = PKCS12_add_safes_ex(safes, NID_pkcs7_data, NULL, NULL);
    out_ptr("add_safes_ex.p12", p12);
    if (p12 != NULL) {
        der = NULL;
        out_int("add_safes_ex.der.len", i2d_PKCS12(p12, &der));
        OPENSSL_free(der);
        der = NULL;
        PKCS12_free(p12);
    }
    sk_PKCS7_pop_free(safes, PKCS7_free);
}

/* ---------------------------------------------------------------------------------------------
 * 10.4's PBE pair and KDF: `PKCS12_PBE_add`, `PKCS12_PBE_keyivgen(_ex)`, the six
 * `builtin_pbe[]` rows' keygen presence (D-PBE-PKCS12-KEYGEN-1's trigger), `PKCS12_key_gen_*`
 * and `PKCS8_set0_pbe(_ex)`.
 * --------------------------------------------------------------------------------------------- */

/* `AlgorithmIdentifier { pbeWithSHA1And3-KeyTripleDES-CBC, PBEPARAM }` -- the input
 * `PKCS8_set0_pbe` encrypts through, and the `ASN1_TYPE` parameter `EVP_PBE_CipherInit_ex`
 * takes. Hand-written so both sides read the same input; `salt` is the first corpus vector's. */
static const unsigned char FIX_PBE_ALG[] = {
    0x30, 0x1b,
      0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03,
      0x30, 0x0d,
        0x04, 0x08, 0x0a, 0x58, 0xcf, 0x64, 0x53, 0x0d, 0x82, 0x3f,
        0x02, 0x01, 0x01
};

/* The six `builtin_pbe[]` rows whose keygen column `D-PBE-PKCS12-KEYGEN-1` names, in table order
 * (indices 4..9 of `EVP_PBE_get`). */
static const int PBE6_NIDS[6] = {
    NID_pbe_WithSHA1And128BitRC4,
    NID_pbe_WithSHA1And40BitRC4,
    NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
    NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
    NID_pbe_WithSHA1And128BitRC2_CBC,
    NID_pbe_WithSHA1And40BitRC2_CBC
};

static void court_pbe_kdf(void)
{
    const unsigned char pass_uni[10] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67, 0x00, 0x00
    };
    unsigned char salt[8] = { 0x0a, 0x58, 0xcf, 0x64, 0x53, 0x0d, 0x82, 0x3f };
    unsigned char out[24];
    EVP_MD *md;
    const unsigned char *p;
    X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *aobj;
    int atype = -1;
    const void *apval = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf;
    X509_SIG *sig;
    ASN1_TYPE param;
    int i;

    PKCS12_PBE_add();

    /* The divergence's own measurement: `EVP_PBE_find_ex` on each of the six NIDs now answers 1
     * with both keygen pointers non-NULL, which is what landing `p12_crpt.c` changes. */
    for (i = 0; i < 6; i++) {
        int cnid = 12345, mnid = 12345, rc;
        EVP_PBE_KEYGEN *kg = NULL;
        EVP_PBE_KEYGEN_EX *kgx = NULL;

        rc = EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, PBE6_NIDS[i], &cnid, &mnid, &kg, &kgx);
        printf("pbe.find.%02d=%d,%d,%d,%d,%d,%s,%s\n", i + 4, rc, EVP_PBE_TYPE_OUTER,
               PBE6_NIDS[i], cnid, mnid, kg != NULL ? "K" : "-", kgx != NULL ? "E" : "-");
        ERR_clear_error();
    }

    /* `EVP_PBE_CipherInit_ex` on the two TripleDES rows, whose ciphers the default provider
     * carries. The RC4/RC2 rows' ciphers are the *legacy* provider's (Phase 13), so a refusal
     * there would measure that stratum's gap rather than this unit's keygen, and they are driven
     * by `EVP_PBE_find_ex` above instead. */
    p = FIX_PBE_ALG;
    alg = d2i_X509_ALGOR(NULL, &p, (long)sizeof(FIX_PBE_ALG));
    if (alg == NULL) {
        printf("pbe.cipherinit.setup=FAIL\n");
        return;
    }
    X509_ALGOR_get0(&aobj, &atype, &apval, alg);
    (void)aobj;
    /* `X509_ALGOR_get0`'s `ppval` is the parameter *value*, not the `ASN1_TYPE`; the client
     * rebuilds the wrapper so `ASN1_TYPE_unpack_sequence` sees a `V_ASN1_SEQUENCE` value. */
    memset(&param, 0, sizeof(param));
    param.type = atype;
    param.value.sequence = (ASN1_STRING *)apval;
    (void)atype;
    for (i = 6; i <= 7; i++) {
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
        ASN1_OBJECT *o = OBJ_nid2obj(PBE6_NIDS[i - 4]);
        int rc;

        ERR_clear_error();
        rc = EVP_PBE_CipherInit_ex(o, "smeg", -1, &param, cctx, 1, NULL, NULL);
        printf("pbe.cipherinit.%02d=%d err=", i, rc);
        {
            unsigned long e = ERR_get_error();

            if (e == 0)
                printf("none\n");
            else
                printf("%d.%d\n", ERR_GET_LIB(e), ERR_GET_REASON(e));
        }
        ERR_clear_error();
        EVP_CIPHER_CTX_free(cctx);
    }

    /* The two `PKCS12_PBE_keyivgen` spellings driven **directly**, which is also what makes them
     * importable symbols of this probe: `EVP_PBE_CipherInit_ex` reaches only the `_ex` one for
     * these six rows (they all carry `keygen_ex`), so the plain spelling's own observable is a
     * direct call. The cipher and digest are the DES3 row's, so the call reaches the same KDF. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", NULL);
        EVP_MD *hmd = EVP_MD_fetch(NULL, "SHA1", NULL);

        if (c != NULL && hmd != NULL) {
            EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

            ERR_clear_error();
            out_int("pbe.keyivgen", PKCS12_PBE_keyivgen(cctx, "smeg", -1, &param, c, hmd, 1));
            out_err("pbe.keyivgen.err");
            EVP_CIPHER_CTX_free(cctx);
            cctx = EVP_CIPHER_CTX_new();
            ERR_clear_error();
            out_int("pbe.keyivgen_ex",
                    PKCS12_PBE_keyivgen_ex(cctx, "smeg", -1, &param, c, hmd, 1, NULL, NULL));
            out_err("pbe.keyivgen_ex.err");
            EVP_CIPHER_CTX_free(cctx);
        } else {
            printf("pbe.keyivgen.setup=FAIL\n");
            printf("pbe.keyivgen_ex.setup=FAIL\n");
        }
        EVP_CIPHER_free(c);
        EVP_MD_free(hmd);
    }

    /* The KDF, through all six spellings. The fixed password `smeg` converts to the first corpus
     * vector's UTF-16BE octets, so `asc`/`utf8`/`uni` all answer that vector's Key. */
    md = EVP_MD_fetch(NULL, "SHA1", NULL);
    if (md == NULL) {
        printf("kdf.setup=FAIL\n");
        X509_ALGOR_free(alg);
        return;
    }
    ERR_clear_error();
    out_int("kdf.uni", PKCS12_key_gen_uni((unsigned char *)pass_uni, 10, salt, 8, 1, 1, 24,
                                          out, md));
    out_hex("kdf.uni.out", out, 24);
    out_int("kdf.uni_ex", PKCS12_key_gen_uni_ex((unsigned char *)pass_uni, 10, salt, 8, 1, 1, 24,
                                                out, md, NULL, NULL));
    out_hex("kdf.uni_ex.out", out, 24);
    out_int("kdf.asc", PKCS12_key_gen_asc("smeg", -1, salt, 8, 1, 1, 24, out, md));
    out_hex("kdf.asc.out", out, 24);
    out_int("kdf.asc_ex", PKCS12_key_gen_asc_ex("smeg", -1, salt, 8, 1, 1, 24, out, md,
                                                 NULL, NULL));
    out_hex("kdf.asc_ex.out", out, 24);
    out_int("kdf.utf8", PKCS12_key_gen_utf8("smeg", -1, salt, 8, 1, 1, 24, out, md));
    out_hex("kdf.utf8.out", out, 24);
    out_int("kdf.utf8_ex", PKCS12_key_gen_utf8_ex("smeg", -1, salt, 8, 1, 1, 24, out, md,
                                                  NULL, NULL));
    out_hex("kdf.utf8_ex.out", out, 24);
    ERR_clear_error();
    EVP_MD_free(md);

    /* `PKCS8_set0_pbe(_ex)`: encrypt the fixed `PrivateKeyInfo` under the fixed TripleDES PBE,
     * printed as the `EncryptedPrivateKeyInfo` DER. The algorithm is adopted by the answer. */
    p = FIX_PKCS8;
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    sig = NULL;
    if (p8inf != NULL) {
        sig = PKCS8_set0_pbe("smeg", -1, p8inf, alg);
        alg = NULL; /* adopted */
        {
            unsigned char *der = NULL;
            int derlen = i2d_X509_SIG(sig, &der);

            out_int("pkcs8.set0_pbe.derlen", derlen);
            out_hex("pkcs8.set0_pbe.der", der, derlen);
            OPENSSL_free(der);
        }
        out_ptr("pkcs8.set0_pbe", sig);
        X509_SIG_free(sig);
    } else {
        out_ptr("pkcs8.set0_pbe", NULL);
    }
    ERR_clear_error();
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    X509_ALGOR_free(alg);

    /* The `_ex` spelling, over its own decode of the same fixture. */
    p = FIX_PBE_ALG;
    alg = d2i_X509_ALGOR(NULL, &p, (long)sizeof(FIX_PBE_ALG));
    p = FIX_PKCS8;
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    if (alg != NULL && p8inf != NULL) {
        sig = PKCS8_set0_pbe_ex("smeg", -1, p8inf, alg, NULL, NULL);
        alg = NULL; /* adopted */
        {
            unsigned char *der = NULL;
            int derlen = i2d_X509_SIG(sig, &der);

            out_int("pkcs8.set0_pbe_ex.derlen", derlen);
            out_hex("pkcs8.set0_pbe_ex.der", der, derlen);
            OPENSSL_free(der);
        }
        X509_SIG_free(sig);
    } else {
        out_ptr("pkcs8.set0_pbe_ex", NULL);
    }
    ERR_clear_error();
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    X509_ALGOR_free(alg);
}

/* The container refusals, each with its coordinate. */
/* The PBE algorithm-identifier builders D443's pull-forward lands: `PKCS8_encrypt(_ex)` and
 * the two `PKCS12_SAFEBAG_create_pkcs8_encrypt[_ex]` spellings. A fixed salt and iteration
 * count are passed so the `EncryptedPrivateKeyInfo` -- and the shrouded key bag over it --
 * are deterministic, and the DER is the observation (docs/PHASE-10-SUBPHASES.md section 3.2). */
static void court_pbe_identifiers(void)
{
    static const unsigned char salt[8] = { 0x0a, 0x58, 0xcf, 0x64, 0x53, 0x0d, 0x82, 0x3f };
    const unsigned char *p;
    PKCS8_PRIV_KEY_INFO *p8inf;
    X509_SIG *sig;
    PKCS12_SAFEBAG *bag;
    unsigned char *der;
    int derlen;

    /* `PKCS8_encrypt`: the PKCS#5 v1.5 arm. The NID names a PBE scheme and not a cipher, so
     * `pbe_nid == -1`'s PBES2 path is not taken and no `RAND` is reached. */
    p = FIX_PKCS8;
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    if (p8inf != NULL) {
        sig = PKCS8_encrypt(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NULL, "smeg", -1,
                            (unsigned char *)salt, 8, 1, p8inf);
        der = NULL;
        derlen = i2d_X509_SIG(sig, &der);
        out_int("pkcs8.encrypt.derlen", derlen);
        out_hex("pkcs8.encrypt.der", der, derlen);
        OPENSSL_free(der);
        out_ptr("pkcs8.encrypt", sig);
        ERR_clear_error();
        X509_SIG_free(sig);
    } else {
        out_int("pkcs8.encrypt.derlen", -1);
    }
    PKCS8_PRIV_KEY_INFO_free(p8inf);

    /* The `_ex` spelling over its own decode of the same fixture. */
    p = FIX_PKCS8;
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    if (p8inf != NULL) {
        sig = PKCS8_encrypt_ex(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NULL, "smeg", -1,
                               (unsigned char *)salt, 8, 1, p8inf, NULL, NULL);
        der = NULL;
        derlen = i2d_X509_SIG(sig, &der);
        out_int("pkcs8.encrypt_ex.derlen", derlen);
        out_hex("pkcs8.encrypt_ex.der", der, derlen);
        OPENSSL_free(der);
        ERR_clear_error();
        X509_SIG_free(sig);
    } else {
        out_int("pkcs8.encrypt_ex.derlen", -1);
    }
    PKCS8_PRIV_KEY_INFO_free(p8inf);

    /* `PKCS12_SAFEBAG_create_pkcs8_encrypt`: the shrouded key bag over that `X509_SIG`. */
    p = FIX_PKCS8;
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    if (p8inf != NULL) {
        bag = PKCS12_SAFEBAG_create_pkcs8_encrypt(NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                                  "smeg", -1, (unsigned char *)salt, 8, 1, p8inf);
        der = NULL;
        derlen = i2d_PKCS12_SAFEBAG(bag, &der);
        out_int("safebag.create_pkcs8_encrypt.derlen", derlen);
        out_hex("safebag.create_pkcs8_encrypt.der", der, derlen);
        OPENSSL_free(der);
        out_int("safebag.create_pkcs8_encrypt.nid",
                bag != NULL ? PKCS12_SAFEBAG_get_nid(bag) : -1);
        ERR_clear_error();
        PKCS12_SAFEBAG_free(bag);
    } else {
        out_int("safebag.create_pkcs8_encrypt.derlen", -1);
    }
    PKCS8_PRIV_KEY_INFO_free(p8inf);

    /* The `_ex` spelling. */
    p = FIX_PKCS8;
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    if (p8inf != NULL) {
        bag = PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                                     "smeg", -1, (unsigned char *)salt, 8, 1,
                                                     p8inf, NULL, NULL);
        der = NULL;
        derlen = i2d_PKCS12_SAFEBAG(bag, &der);
        out_int("safebag.create_pkcs8_encrypt_ex.derlen", derlen);
        out_hex("safebag.create_pkcs8_encrypt_ex.der", der, derlen);
        OPENSSL_free(der);
        ERR_clear_error();
        PKCS12_SAFEBAG_free(bag);
    } else {
        out_int("safebag.create_pkcs8_encrypt_ex.derlen", -1);
    }
    PKCS8_PRIV_KEY_INFO_free(p8inf);
}

static void court_container_refusals(void)
{
    static const unsigned char secret_a[3] = { 0x01, 0x02, 0x03 };
    STACK_OF(PKCS12_SAFEBAG) *bags;
    PKCS7 *p7, *enc;

    /* `PKCS12_unpack_p7data` on a non-`data` contentInfo: refused with the container reason. */
    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_encrypted);
    ERR_clear_error();
    out_ptr("refuse.unpack_p7data_type", PKCS12_unpack_p7data(p7));
    out_err("refuse.unpack_p7data_type.err");

    /* `PKCS12_unpack_p7encdata` on a `data` contentInfo: NULL with a clean queue, because the
     * authority's arm for it raises nothing. */
    bags = make_bags(secret_a, 3);
    enc = PKCS12_pack_p7data(bags);
    ERR_clear_error();
    out_ptr("refuse.unpack_p7encdata_type", PKCS12_unpack_p7encdata(enc, "pw", -1));
    out_err("refuse.unpack_p7encdata_type.err");

    PKCS7_free(enc);
    PKCS7_free(p7);
}

/* ---------------------------------------------------------------------------------------------
 * 10.3's second slice: the MAC, the RFC 9879 PBMAC1 MAC, the encrypted contentInfo, the
 * `add_key`/`add_safe` surface and the password change.
 *
 * Everything below takes a fixed salt and iteration count where the authority would otherwise
 * draw one, so the bytes are a function of the fixed input alone (docs/PHASE-10-SUBPHASES.md
 * section 3.2). `PKCS12_newpass` prints the container before and after its deterministic data-arm
 * repack.
 * --------------------------------------------------------------------------------------------- */

/* An `NID_pkcs7_data` container over one fixed secretBag. The caller frees it. */
static PKCS12 *container_one(void)
{
    static const unsigned char secret[3] = { 0x01, 0x02, 0x03 };
    STACK_OF(PKCS7) *safes = sk_PKCS7_new_null();
    PKCS7 *p7 = PKCS12_pack_p7data(make_bags(secret, 3));
    PKCS12 *p12;

    if (p7 != NULL)
        sk_PKCS7_push(safes, p7);
    p12 = PKCS12_add_safes(safes, NID_pkcs7_data);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    return p12;
}

static void court_mac(void)
{
    static unsigned char maccsalt[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    PKCS12 *p12;
    unsigned char *der = NULL;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    long len;
    const ASN1_OCTET_STRING *digest = NULL, *msalt = NULL;
    const X509_ALGOR *malg = NULL;
    const ASN1_INTEGER *miter = NULL;

    p12 = container_one();
    out_ptr("mac2.p12", p12);
    if (p12 == NULL)
        return;

    /* No MacData yet: `mac_present` is 0 and `verify_mac` refuses with `PKCS12_R_MAC_ABSENT`. */
    out_int("mac2.present_before", PKCS12_mac_present(p12));
    ERR_clear_error();
    out_int("mac2.verify_absent", PKCS12_verify_mac(p12, "smeg", -1));
    out_err("mac2.verify_absent.err");

    /* `PKCS12_set_mac` over a fixed salt and iteration count. */
    out_int("mac2.set", PKCS12_set_mac(p12, "smeg", -1, maccsalt, 8, 0x0800, EVP_sha256()));
    out_int("mac2.present_after", PKCS12_mac_present(p12));
    PKCS12_get0_mac(&digest, &malg, &msalt, &miter, p12);
    out_int("mac2.iter", ASN1_INTEGER_get(miter));
    out_int("mac2.alg.nid", malg != NULL ? OBJ_obj2nid(malg->algorithm) : -1);
    out_hex("mac2.salt", ASN1_STRING_get0_data(msalt), ASN1_STRING_length(msalt));
    out_int("mac2.digest.len", ASN1_STRING_length(digest));
    out_hex("mac2.digest", ASN1_STRING_get0_data(digest), ASN1_STRING_length(digest));

    /* `PKCS12_gen_mac` recomputes the same HMAC independently of the stored octets. */
    ERR_clear_error();
    out_int("mac2.gen", PKCS12_gen_mac(p12, "smeg", -1, mac, &maclen));
    out_int("mac2.gen.len", (long)maclen);
    out_hex("mac2.gen.hex", mac, (long)maclen);
    out_err("mac2.gen.err");

    /* The DER carries the MacData as its last column; the bytes are the document. */
    len = i2d_PKCS12(p12, &der);
    out_int("mac2.der.len", len);
    out_hex("mac2.der", der, len);
    OPENSSL_free(der);
    der = NULL;

    /* Verify both ways: the right password matches, the wrong one answers 0 without raising. */
    ERR_clear_error();
    out_int("mac2.verify_ok", PKCS12_verify_mac(p12, "smeg", -1));
    out_err("mac2.verify_ok.err");
    ERR_clear_error();
    out_int("mac2.verify_bad", PKCS12_verify_mac(p12, "wrong", -1));
    out_err("mac2.verify_bad.err");

    PKCS12_free(p12);
}

static void court_pbmac1(void)
{
    static unsigned char maccsalt[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    PKCS12 *p12;
    unsigned char *der = NULL;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    long len;
    const ASN1_OCTET_STRING *digest = NULL, *msalt = NULL;
    const X509_ALGOR *malg = NULL;
    const ASN1_INTEGER *miter = NULL;

    p12 = container_one();
    out_ptr("pbmac1.p12", p12);
    if (p12 == NULL)
        return;

    ERR_clear_error();
    out_int("pbmac1.set",
            PKCS12_set_pbmac1_pbkdf2(p12, "smeg", -1, maccsalt, 8, 0x0800, EVP_sha256(), NULL));
    out_err("pbmac1.set.err");
    PKCS12_get0_mac(&digest, &malg, &msalt, &miter, p12);
    out_int("pbmac1.iter", ASN1_INTEGER_get(miter));
    out_int("pbmac1.alg.nid", malg != NULL ? OBJ_obj2nid(malg->algorithm) : -1);
    out_hex("pbmac1.salt", ASN1_STRING_get0_data(msalt), ASN1_STRING_length(msalt));
    out_hex("pbmac1.digest", ASN1_STRING_get0_data(digest), ASN1_STRING_length(digest));

    ERR_clear_error();
    out_int("pbmac1.gen", PKCS12_gen_mac(p12, "smeg", -1, mac, &maclen));
    out_hex("pbmac1.gen.hex", mac, (long)maclen);
    out_err("pbmac1.gen.err");

    /* The RFC 9879 `PBMAC1PARAM` is inside the container's MacData parameter. */
    len = i2d_PKCS12(p12, &der);
    out_int("pbmac1.der.len", len);
    out_hex("pbmac1.der", der, len);
    OPENSSL_free(der);

    ERR_clear_error();
    out_int("pbmac1.verify_ok", PKCS12_verify_mac(p12, "smeg", -1));
    out_err("pbmac1.verify_ok.err");
    ERR_clear_error();
    out_int("pbmac1.verify_bad", PKCS12_verify_mac(p12, "wrong", -1));
    out_err("pbmac1.verify_bad.err");

    PKCS12_free(p12);
}

static void court_p7encdata(void)
{
    static unsigned char salt[8] = { 0x0a, 0x58, 0xcf, 0x64, 0x53, 0x0d, 0x82, 0x3f };
    static const unsigned char secret[3] = { 0x01, 0x02, 0x03 };
    STACK_OF(PKCS12_SAFEBAG) *bags;
    PKCS7 *p7;

    /* A PKCS#5 v1.5 cipher derives its IV from the salt, so a fixed salt gives fixed octets. */
    bags = make_bags(secret, 3);
    p7 = PKCS12_pack_p7encdata(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, "smeg", -1, salt, 8, 1,
                               bags);
    out_ptr("p7enc.p7", p7);
    if (p7 != NULL) {
        out_int("p7enc.type", OBJ_obj2nid(p7->type));
        out_int("p7enc.alg", OBJ_obj2nid(p7->d.encrypted->enc_data->algorithm->algorithm));
        out_int("p7enc.content_type", OBJ_obj2nid(p7->d.encrypted->enc_data->content_type));
        out_int("p7enc.encdata.len", p7->d.encrypted->enc_data->enc_data->length);
        out_hex("p7enc.encdata", p7->d.encrypted->enc_data->enc_data->data,
                p7->d.encrypted->enc_data->enc_data->length);
        PKCS7_free(p7);
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);

    /* The `_ex` spelling over its own stack: the same bytes, since the inputs are the same. */
    bags = make_bags(secret, 3);
    p7 = PKCS12_pack_p7encdata_ex(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, "smeg", -1, salt, 8, 1,
                                  bags, NULL, NULL);
    out_ptr("p7enc_ex.p7", p7);
    if (p7 != NULL) {
        out_int("p7enc_ex.alg", OBJ_obj2nid(p7->d.encrypted->enc_data->algorithm->algorithm));
        out_int("p7enc_ex.encdata.len", p7->d.encrypted->enc_data->enc_data->length);
        out_hex("p7enc_ex.encdata", p7->d.encrypted->enc_data->enc_data->data,
                p7->d.encrypted->enc_data->enc_data->length);
        PKCS7_free(p7);
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
}

static void court_add_key(void)
{
    const unsigned char *p;
    EVP_PKEY *pkey;
    PKCS12_SAFEBAG *bag;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    unsigned char *der = NULL;
    long len;

    p = rsa_pkcs8_der;
    pkey = d2i_AutoPrivateKey(NULL, &p, (long)sizeof(rsa_pkcs8_der));
    out_ptr("add_key.pkey", pkey);
    if (pkey == NULL)
        return;
    out_int("add_key.pkey.id", EVP_PKEY_get_id(pkey));
    out_int("add_key.pkey.bits", EVP_PKEY_get_bits(pkey));

    /* `nid_key == -1` builds the unencrypted `keyBag`, whose bytes are the fixed key's. */
    bag = PKCS12_add_key(&bags, pkey, 0, 0x0800, -1, "smeg");
    out_ptr("add_key.bag", bag);
    if (bag != NULL) {
        out_int("add_key.bag_nid", PKCS12_SAFEBAG_get_nid(bag));
        out_int("add_key.num", sk_PKCS12_SAFEBAG_num(bags));
        len = i2d_PKCS12_SAFEBAG(bag, &der);
        out_hex("add_key.der", der, len);
        OPENSSL_free(der);
        der = NULL;
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;

    /* The `_ex` spelling over the same key, with a key-usage attribute on the PKCS#8. */
    bag = PKCS12_add_key_ex(&bags, pkey, 0x80, 0x0800, -1, "smeg", NULL, NULL);
    out_ptr("add_key_ex.bag", bag);
    if (bag != NULL) {
        out_int("add_key_ex.bag_nid", PKCS12_SAFEBAG_get_nid(bag));
        out_int("add_key_ex.num", sk_PKCS12_SAFEBAG_num(bags));
        len = i2d_PKCS12_SAFEBAG(bag, &der);
        out_hex("add_key_ex.der", der, len);
        OPENSSL_free(der);
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    EVP_PKEY_free(pkey);
}

static void court_add_safe(void)
{
    static const unsigned char secret_a[3] = { 0x01, 0x02, 0x03 };
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    PKCS12 *p12;
    unsigned char *der = NULL;
    long len;

    /* The plain arm (`nid_safe == -1`): the packed `NID_pkcs7_data` contentInfo. */
    bags = make_bags(secret_a, 3);
    out_int("add_safe.plain", PKCS12_add_safe(&safes, bags, -1, 0, NULL));
    out_int("add_safe.num", safes != NULL ? sk_PKCS7_num(safes) : -1);
    if (safes != NULL && sk_PKCS7_num(safes) == 1)
        out_int("add_safe.type", OBJ_obj2nid(sk_PKCS7_value(safes, 0)->type));
    p12 = PKCS12_add_safes(safes, 0);
    out_ptr("add_safe.container", p12);
    if (p12 != NULL) {
        len = i2d_PKCS12(p12, &der);
        out_hex("add_safe.der", der, len);
        OPENSSL_free(der);
        der = NULL;
        PKCS12_free(p12);
    }
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);

    /* The `_ex` spelling over its own stack. */
    safes = NULL;
    bags = make_bags(secret_a, 3);
    out_int("add_safe_ex.plain", PKCS12_add_safe_ex(&safes, bags, -1, 0, NULL, NULL, NULL));
    out_int("add_safe_ex.num", safes != NULL ? sk_PKCS7_num(safes) : -1);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);

    /* The encrypted arm (`nid_safe != -1`): the salt is drawn, so only the structure is fixed. */
    safes = NULL;
    bags = make_bags(secret_a, 3);
    out_int("add_safe.pbe",
            PKCS12_add_safe(&safes, bags, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 0x0800, "smeg"));
    out_int("add_safe.pbe.num", safes != NULL ? sk_PKCS7_num(safes) : -1);
    if (safes != NULL && sk_PKCS7_num(safes) == 1)
        out_int("add_safe.pbe.type", OBJ_obj2nid(sk_PKCS7_value(safes, 0)->type));
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
}

static void court_newpass(void)
{
    static unsigned char maccsalt[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    PKCS12 *p12;
    unsigned char *der = NULL;
    long len;

    /* A NULL container is refused with its own coordinate. */
    ERR_clear_error();
    out_int("newpass.null", PKCS12_newpass(NULL, "a", "b"));
    out_err("newpass.null.err");

    /* A fixed-salt MAC over a data authsafe: the data-arm repack is deterministic, so the
     * before/after DER is the document. */
    p12 = container_one();
    PKCS12_set_mac(p12, "smeg", -1, maccsalt, 8, 0x0800, EVP_sha256());
    len = i2d_PKCS12(p12, &der);
    out_hex("newpass.der_before", der, len);
    OPENSSL_free(der);
    der = NULL;

    ERR_clear_error();
    out_int("newpass.change", PKCS12_newpass(p12, "smeg", "newpass"));
    out_err("newpass.change.err");
    len = i2d_PKCS12(p12, &der);
    out_int("newpass.der_after.len", len);
    out_hex("newpass.der_after", der, len);
    OPENSSL_free(der);
    der = NULL;
    ERR_clear_error();
    out_int("newpass.verify_new", PKCS12_verify_mac(p12, "newpass", -1));
    out_err("newpass.verify_new.err");
    ERR_clear_error();
    out_int("newpass.verify_old", PKCS12_verify_mac(p12, "smeg", -1));
    out_err("newpass.verify_old.err");
    PKCS12_free(p12);

    /* A wrong old password is refused before any repack, with its own coordinate. */
    p12 = container_one();
    PKCS12_set_mac(p12, "smeg", -1, maccsalt, 8, 0x0800, EVP_sha256());
    ERR_clear_error();
    out_int("newpass.wrong_old", PKCS12_newpass(p12, "wrong", "newpass"));
    out_err("newpass.wrong_old.err");
    PKCS12_free(p12);
}

/* ---------------------------------------------------------------------------------------------
 * The certificate bag builders and the container builder (10.15).
 *
 * The certificate and CRL are decoded from the **shared fixed DER** (`rt_x509_der.h`), so the
 * `certBag` bytes, the decoded certificate's re-encoded bytes and the plain `PFX` are all
 * functions of fixed input. `PKCS12_create` is driven with `nid_cert == -1` and `mac_iter == -1`,
 * which selects the unencrypted `data` contentInfo and no MAC, so no salt or IV is drawn and the
 * DER is byte-comparable (the authority's default AES arm and MAC would both be random).
 * --------------------------------------------------------------------------------------------- */

static void court_cert_bags(void)
{
    const unsigned char *p;
    unsigned char *der = NULL;
    X509 *cert = NULL, *cert2 = NULL;
    X509_CRL *crl = NULL, *crl2 = NULL;
    PKCS12_SAFEBAG *bag = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    PKCS12 *p12 = NULL;
    long len;

    p = RT_X509_CERT_DER;
    cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    p = RT_X509_CRL_DER;
    crl = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    out_ptr("certbags.cert", cert);
    out_ptr("certbags.crl", crl);

    /* `PKCS12_SAFEBAG_create_cert` / `_get1_cert`: the bag DER and the decoded DER. */
    ERR_clear_error();
    bag = PKCS12_SAFEBAG_create_cert(cert);
    out_ptr("certbags.create_cert", bag);
    out_err("certbags.create_cert.err");
    if (bag != NULL) {
        out_int("certbags.create_cert.nid", PKCS12_SAFEBAG_get_nid(bag));
        out_int("certbags.create_cert.bag_nid", PKCS12_SAFEBAG_get_bag_nid(bag));
        len = i2d_PKCS12_SAFEBAG(bag, &der);
        out_hex("certbags.create_cert.der", der, len);
        OPENSSL_free(der);
        der = NULL;
        cert2 = PKCS12_SAFEBAG_get1_cert(bag);
        out_ptr("certbags.get1_cert", cert2);
        len = i2d_X509(cert2, &der);
        out_hex("certbags.get1_cert.der", der, len);
        OPENSSL_free(der);
        der = NULL;
        X509_free(cert2);
        PKCS12_SAFEBAG_free(bag);
    }

    ERR_clear_error();
    bag = PKCS12_SAFEBAG_create_cert(cert);
    cert2 = PKCS12_SAFEBAG_get1_cert_ex(bag, NULL, NULL);
    out_ptr("certbags.get1_cert_ex", cert2);
    out_err("certbags.get1_cert_ex.err");
    X509_free(cert2);
    PKCS12_SAFEBAG_free(bag);

    /* `PKCS12_SAFEBAG_create_crl` / `_get1_crl`. */
    ERR_clear_error();
    bag = PKCS12_SAFEBAG_create_crl(crl);
    out_ptr("certbags.create_crl", bag);
    out_err("certbags.create_crl.err");
    if (bag != NULL) {
        out_int("certbags.create_crl.nid", PKCS12_SAFEBAG_get_nid(bag));
        out_int("certbags.create_crl.bag_nid", PKCS12_SAFEBAG_get_bag_nid(bag));
        len = i2d_PKCS12_SAFEBAG(bag, &der);
        out_hex("certbags.create_crl.der", der, len);
        OPENSSL_free(der);
        der = NULL;
        crl2 = PKCS12_SAFEBAG_get1_crl(bag);
        out_ptr("certbags.get1_crl", crl2);
        len = i2d_X509_CRL(crl2, &der);
        out_hex("certbags.get1_crl.der", der, len);
        OPENSSL_free(der);
        der = NULL;
        X509_CRL_free(crl2);
        PKCS12_SAFEBAG_free(bag);
    }

    ERR_clear_error();
    bag = PKCS12_SAFEBAG_create_crl(crl);
    crl2 = PKCS12_SAFEBAG_get1_crl_ex(bag, NULL, NULL);
    out_ptr("certbags.get1_crl_ex", crl2);
    out_err("certbags.get1_crl_ex.err");
    X509_CRL_free(crl2);
    PKCS12_SAFEBAG_free(bag);

    /* `PKCS12_add_cert`: it builds the collection itself and hands the bag back. */
    ERR_clear_error();
    bag = PKCS12_add_cert(&bags, cert);
    out_ptr("certbags.add_cert", bag);
    out_err("certbags.add_cert.err");
    out_int("certbags.add_cert.num", bags != NULL ? sk_PKCS12_SAFEBAG_num(bags) : -1);
    if (bag != NULL) {
        len = i2d_PKCS12_SAFEBAG(bag, &der);
        out_hex("certbags.add_cert.der", der, len);
        OPENSSL_free(der);
        der = NULL;
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;

    /* The unencrypted, MAC-free container: same `PFX` from all three spellings. */
    ERR_clear_error();
    p12 = PKCS12_create("pass", "name", NULL, cert, NULL, -1, -1, 1, -1, 0);
    out_ptr("certbags.create", p12);
    out_err("certbags.create.err");
    len = i2d_PKCS12(p12, &der);
    out_hex("certbags.create.der", der, len);
    OPENSSL_free(der);
    der = NULL;
    PKCS12_free(p12);

    ERR_clear_error();
    p12 = PKCS12_create_ex("pass", "name", NULL, cert, NULL, -1, -1, 1, -1, 0, NULL, NULL);
    out_ptr("certbags.create_ex", p12);
    out_err("certbags.create_ex.err");
    len = i2d_PKCS12(p12, &der);
    out_hex("certbags.create_ex.der", der, len);
    OPENSSL_free(der);
    der = NULL;
    PKCS12_free(p12);

    ERR_clear_error();
    p12 = PKCS12_create_ex2("pass", "name", NULL, cert, NULL, -1, -1, 1, -1, 0, NULL, NULL,
                            NULL, NULL);
    out_ptr("certbags.create_ex2", p12);
    out_err("certbags.create_ex2.err");
    len = i2d_PKCS12(p12, &der);
    out_hex("certbags.create_ex2.der", der, len);
    OPENSSL_free(der);
    der = NULL;
    PKCS12_free(p12);

    /* A `certBag` is not a `crlBag` and a `secretBag` is neither; each refusal is its own read
     * with no error raised. */
    bag = PKCS12_SAFEBAG_create_cert(cert);
    ERR_clear_error();
    out_ptr("certbags.get1_crl_of_cert", PKCS12_SAFEBAG_get1_crl(bag));
    out_err("certbags.get1_crl_of_cert.err");
    PKCS12_SAFEBAG_free(bag);

    X509_free(cert);
    X509_CRL_free(crl);
}

/* ---------------------------------------------------------------------------------------------
 * `PKCS12_parse` (10.17): the simplified read path, driven over the fixed matching pair.
 *
 * A container is built by `PKCS12_create` from `FIX_CERT_KEY` and `RT_X509_CERT_DER` -- a real
 * `(private key, certificate)` pair, which `PKCS12_create` requires (`X509_check_private_key`) --
 * with a second copy of the certificate in the `ca` stack and a **fixed-salt** MAC stamped on, so
 * the MAC check the parse runs first is deterministic (`PKCS12_create`'s own salt is random). The
 * container is then `i2d_PKCS12`'d and read back through `d2i_PKCS12`, so both sides parse the
 * encoder's document rather than one side's in-memory structure. Every observation is a fixed
 * function of those inputs: the recovered key's identity, the certificate and CA stack counts,
 * each recovered certificate's serial and re-encoded DER, and the wrong-password and
 * NULL-container refusals with their error coordinates. No pointer address is printed.
 * --------------------------------------------------------------------------------------------- */

/* One `STACK_OF(X509)` as `base.num` and, for each element, `base.NN.serial` and `base.NN.der`.
 * A NULL stack prints `base.num=-1`, so "the parse left no CA stack" is itself an observation. */
static void out_cert_stack(const char *base, STACK_OF(X509) *sk)
{
    char key[48];
    int i, n = sk != NULL ? sk_X509_num(sk) : -1;

    snprintf(key, sizeof(key), "%s.num", base);
    out_int(key, n);
    for (i = 0; i < n; i++) {
        X509 *x = sk_X509_value(sk, i);
        unsigned char *der = NULL;
        long len;

        snprintf(key, sizeof(key), "%s.%02d.serial", base, i);
        out_int(key, ASN1_INTEGER_get(X509_get_serialNumber(x)));
        snprintf(key, sizeof(key), "%s.%02d.der", base, i);
        len = i2d_X509(x, &der);
        out_hex(key, der, len);
        OPENSSL_free(der);
    }
}

static void court_parse(void)
{
    static unsigned char maccsalt[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const unsigned char *p;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *cap = NULL;
    PKCS12 *p12 = NULL, *rt = NULL;
    unsigned char *der = NULL;
    long len;

    /* The fixed matching pair. `cap` borrows `cert`; `PKCS12_create` copies both into bags. */
    p = FIX_CERT_KEY;
    pkey = d2i_AutoPrivateKey(NULL, &p, (long)sizeof(FIX_CERT_KEY));
    p = RT_X509_CERT_DER;
    cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    out_ptr("parse.pkey_in", pkey);
    out_ptr("parse.cert_in", cert);
    if (pkey == NULL || cert == NULL)
        goto done;
    cap = sk_X509_new_null();
    sk_X509_push(cap, cert);

    /* The unencrypted key and certificate bags (a plain `data` contentInfo), then a fixed-salt
     * MAC; `create`'s own MAC (and its salt) is skipped with `mac_iter == -1`. */
    ERR_clear_error();
    p12 = PKCS12_create("pass", "name", pkey, cert, cap, -1, -1, 1, -1, 0);
    out_ptr("parse.create", p12);
    out_err("parse.create.err");
    if (p12 == NULL)
        goto done;
    out_int("parse.set_mac", PKCS12_set_mac(p12, "pass", -1, maccsalt, 8, 0x0800, EVP_sha256()));

    /* The bytes the parse sees are the encoder's, so both sides read the same document. */
    len = i2d_PKCS12(p12, &der);
    out_int("parse.der.len", len);
    p = der;
    rt = d2i_PKCS12(NULL, &p, len);
    out_ptr("parse.rt", rt);
    OPENSSL_free(der);
    der = NULL;
    if (rt == NULL)
        goto done;

    /* The success arm: the MAC verifies, the key bag supplies the key, the first matching
     * certificate becomes `*cert`, and the second (the `ca` copy) goes to `*ca`. */
    {
        EVP_PKEY *key = NULL;
        X509 *got = NULL;
        STACK_OF(X509) *ca = NULL;

        ERR_clear_error();
        out_int("parse.ret", PKCS12_parse(rt, "pass", &key, &got, &ca));
        out_err("parse.err");
        out_ptr("parse.key", key);
        out_int("parse.key.id", key != NULL ? EVP_PKEY_get_id(key) : -1);
        if (key != NULL) {
            const char *tn = EVP_PKEY_get0_type_name(key);

            out_hex("parse.key.type", (const unsigned char *)tn,
                    tn != NULL ? (long)strlen(tn) : 0);
        }
        out_ptr("parse.cert", got);
        out_int("parse.cert.serial",
                got != NULL ? ASN1_INTEGER_get(X509_get_serialNumber(got)) : -1);
        if (got != NULL) {
            der = NULL;
            len = i2d_X509(got, &der);
            out_hex("parse.cert.der", der, len);
            OPENSSL_free(der);
            der = NULL;
        }
        out_ptr("parse.ca", ca);
        out_cert_stack("parse.ca", ca);

        EVP_PKEY_free(key);
        X509_free(got);
        sk_X509_pop_free(ca, X509_free);
    }

    /* `cert == NULL`, `ca != NULL`: nothing can match into `*cert`, so every recovered
     * certificate is appended to `*ca` -- both identical bags land there. */
    {
        EVP_PKEY *key = NULL;
        STACK_OF(X509) *ca = NULL;

        ERR_clear_error();
        out_int("parse.allca.ret", PKCS12_parse(rt, "pass", &key, NULL, &ca));
        out_err("parse.allca.err");
        out_ptr("parse.allca.key", key);
        out_cert_stack("parse.allca.ca", ca);

        EVP_PKEY_free(key);
        sk_X509_pop_free(ca, X509_free);
    }

    /* The refusal arm: a wrong password fails the `MacData` check, with its coordinate. */
    {
        EVP_PKEY *key = NULL;
        X509 *got = NULL;
        STACK_OF(X509) *ca = NULL;

        ERR_clear_error();
        out_int("parse.wrong.ret", PKCS12_parse(rt, "wrong", &key, &got, &ca));
        out_err("parse.wrong.err");
        out_ptr("parse.wrong.key", key);
        out_ptr("parse.wrong.cert", got);
        out_ptr("parse.wrong.ca", ca);

        EVP_PKEY_free(key);
        X509_free(got);
        sk_X509_pop_free(ca, X509_free);
    }

    /* The NULL-argument arm: a NULL container is refused before any column is read. */
    {
        EVP_PKEY *key = NULL;
        X509 *got = NULL;
        STACK_OF(X509) *ca = NULL;

        ERR_clear_error();
        out_int("parse.null.ret", PKCS12_parse(NULL, "pass", &key, &got, &ca));
        out_err("parse.null.err");
        out_ptr("parse.null.key", key);
        out_ptr("parse.null.cert", got);
        out_ptr("parse.null.ca", ca);

        EVP_PKEY_free(key);
        X509_free(got);
        sk_X509_pop_free(ca, X509_free);
    }

 done:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_free(cap);
    PKCS12_free(rt);
    PKCS12_free(p12);
    OPENSSL_free(der);
}

/* ---------------------------------------------------------------------------------------------
 * The refusals, each with the error queue.
 * --------------------------------------------------------------------------------------------- */

static void court_refusals(void)
{
    static const unsigned char secret_val[3] = { 0x01, 0x02, 0x03 };
    PKCS12_SAFEBAG *bad, *db;

    ERR_clear_error();
    bad = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_UTF8STRING, secret_val, 3);
    out_ptr("refuse.secret_bad_vtype", bad);
    out_err("refuse.secret_bad_vtype.err");

    db = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 3);
    out_int("refuse.dup_friendly_first", PKCS12_add_friendlyname_asc(db, "x", -1));
    ERR_clear_error();
    out_int("refuse.dup_friendly_second", PKCS12_add_friendlyname_asc(db, "y", -1));
    out_err("refuse.dup_friendly.err");
    PKCS12_SAFEBAG_free(db);
}

int main(void)
{
    court_items();
    court_unicode();
    court_safebag();
    court_attr_writers();
    court_keybags();
    court_items_roundtrip();
    court_add3();
    court_container();
    court_container_refusals();
    court_pbe_kdf();
    court_pbe_identifiers();
    court_refusals();
    court_mac();
    court_pbmac1();
    court_p7encdata();
    court_add_key();
    court_add_safe();
    court_newpass();
    court_cert_bags();
    court_parse();
    return 0;
}
