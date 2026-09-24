/*
 * RT-ASYM-CIPHER -- Phase 8.4's `OSSL_OP_ASYM_CIPHER` and `OSSL_OP_KEM` registration-row court.
 *
 * Why this court exists
 * ---------------------
 * `provider_court_coverage.py` (D245) requires every row the census calls `implemented` to be named
 * by a probe of a differential court, and naming is not driving. Two registration rows landed with
 * the RSA encryption units had no arm that touched them:
 *
 *   * `providers/implementations/asymciphers/rsa_enc.c.in`'s `OSSL_OP_ASYM_CIPHER` row
 *     (`ossl_rsa_asym_cipher_functions`), and
 *   * `providers/implementations/kem/rsa_kem.c.in`'s `OSSL_OP_KEM` row
 *     (`ossl_rsa_asym_kem_functions`).
 *
 * `RT-KEYMGMT` drives the `RSA` keymgmt row both key through and `RT-SIGNATURE` drives the `RSA`
 * signature rows; neither touches the encryption faces. This probe does: each row is fetched by
 * name, the key is imported through the `RSA` keymgmt row, and the arms below drive encrypt/decrypt
 * and encapsulate/decapsulate, observing the return codes, the buffer sizes, the parameter round
 * trips and the refusals.
 *
 * ## The two rows, and the operations that select them
 *
 * `EVP_ASYM_CIPHER_fetch(NULL, "RSA", NULL)` and `EVP_KEM_fetch(NULL, "RSA", NULL)` reach the rows
 * directly by name; `EVP_PKEY_encrypt_init_ex`/`EVP_PKEY_encapsulate_init` reach them through the
 * key's own `query_operation_name`, which is `RSA` for both. Both entry points are driven, because
 * the direct fetch and the key-driven resolution dispatch through different machinery and a row that
 * answered one could refuse the other.
 *
 * ## Why the key constants are read back rather than typed (D392's lesson)
 *
 * The 2048-bit private key is the same one `RT-SIGNATURE`'s `RSA` arm drives: every component was
 * printed once by a one-off program linked against the admitted authority, through
 * `EVP_PKEY_get_bn_param`, in `OSSL_PARAM_construct_BN`'s native byte order. Nothing here is a typed
 * constant the two sides could agree on while both being wrong. The **padding-mode numbers are not
 * typed either**: they come from `include/openssl/rsa.h`, which each side compiles against.
 *
 * ## The error queue is drained, and for the KEM that is the strongest observation here
 *
 * Every refusal arm calls `drain`, which prints each record's packed code **and its file:line:func
 * coordinate**. That coordinate is the authority's, and the candidate's is what
 * `src/runtime/err_sites.rs` reconstructed -- so the drain is what makes the KEM's one run-time-chosen
 * reason observable at all (`rsa_kem.c:541`, `ERR_LIB_RSA` with `RSA_R_DATA_TOO_SMALL` for
 * `c in {0, 1}` or `RSA_R_DATA_TOO_LARGE_FOR_MODULUS` for `c in {n-1, n}`). All four ciphertexts are
 * built from the authority-read modulus rather than typed, so the two sides cannot agree on a wrong
 * `n`.
 *
 * ## What this court deliberately does not observe
 *
 *   * **Any ciphertext or shared secret.** PKCS#1 v1.5, OAEP and the RSASVE encapsulation are
 *     randomised, so what is printed is a length and a round-trip verdict. The `none`-padding arm is
 *     the exception and the byte-order canary: `RSAEP` with no padding is a deterministic function of
 *     the fixed modulus and exponent, so its ciphertext **is** printed -- that arm notices a wrong
 *     `n`, `e` or native byte order, which is the one class of error the randomised arms cannot see.
 *   * **`RSA_PKCS1_WITH_TLS_PADDING`'s successful long path.** It needs a real TLS premaster secret;
 *     the probe observes the mode's size query and its `client_version == 0` refusal, which is the
 *     whole of the mode's contract a fixed input can reach.
 *   * **Any generated key.** `EVP_PKEY_fromdata` imports the fixed constants; nothing is generated,
 *     so two runs of the same side agree.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>

/* `SSL_MAX_MASTER_KEY_LENGTH` -- `include/openssl/prov_ssl.h`, the length the TLS-padding decrypt
 * size query answers. */
#define ASYM_TLS_MASTER_LEN 48

static void kv_int(const char *key, int value)
{
    printf("%s=%d\n", key, value);
}

static void kv_str(const char *key, const char *value)
{
    printf("%s=%s\n", key, value == NULL ? "(null)" : value);
}

static void kv_hex(const char *key, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", key);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* Drain the queue, printing each record's packed code, its file:line:func coordinate and the count.
 * Every refusal arm below uses this: the coordinate is the authority's `ERR_set_debug` triple, which
 * `src/runtime/err_sites.rs` reconstructed, and a record both sides raise with a different line is a
 * residual rather than an invisible agreement. */
static void drain(const char *arm)
{
    int n = 0;

    for (;;) {
        const char *file = NULL;
        const char *func = NULL;
        int line = 0;
        unsigned long e = ERR_get_error_all(&file, &line, &func, NULL, NULL);

        if (e == 0)
            break;
        printf("asym.%s.err.%d=%lu:%s:%d:%s\n", arm, n, e,
               file != NULL ? file : "(null)", line,
               func != NULL ? func : "(null)");
        n++;
    }
    printf("asym.%s.err.count=%d\n", arm, n);
}

/* The fixed 2048-bit RSA private key: the same authority-derived value `RT-SIGNATURE`'s `RSA` arm
 * carries. Every byte was printed once by a one-off program linked against the admitted authority,
 * through `EVP_PKEY_get_bn_param`, in `OSSL_PARAM_construct_BN`'s native byte order (D392). */
static const unsigned char rsa_probe_n[256] = {
    0xb1, 0xac, 0x85, 0x8f, 0x39, 0x8d, 0x1c, 0x66, 0x68, 0x4e, 0xef, 0x86,
    0x5f, 0x3f, 0x9e, 0x3e, 0x9e, 0x26, 0x51, 0x65, 0x92, 0xe2, 0xe5, 0x50,
    0x65, 0x6a, 0x81, 0x81, 0x3a, 0x71, 0xc7, 0x10, 0xf1, 0xe2, 0xe5, 0x78,
    0x43, 0x52, 0xb4, 0x82, 0x4e, 0xbb, 0x5c, 0x74, 0x84, 0x51, 0xe4, 0x1c,
    0xc4, 0x3b, 0x07, 0x99, 0x76, 0x3a, 0xcc, 0x33, 0xcc, 0x71, 0xa9, 0x63,
    0x99, 0x06, 0xe4, 0x9c, 0xbe, 0x6b, 0x7b, 0x29, 0xe0, 0xf7, 0x4c, 0xe2,
    0xb8, 0x2c, 0x11, 0x40, 0x04, 0xa5, 0x9c, 0x2a, 0x49, 0x62, 0x1c, 0x32,
    0xa5, 0x46, 0xbe, 0x56, 0x95, 0xbe, 0x9e, 0x1a, 0x15, 0x9e, 0x12, 0xd1,
    0x67, 0x7a, 0x7e, 0x2f, 0xde, 0xa4, 0x98, 0x73, 0x07, 0x6b, 0x03, 0x27,
    0x25, 0x9a, 0x05, 0xf6, 0x17, 0x89, 0xc2, 0x8f, 0x3a, 0x9e, 0xeb, 0x47,
    0x7d, 0x8b, 0x8f, 0x82, 0x37, 0x53, 0x12, 0x74, 0x57, 0x39, 0xa5, 0x94,
    0x6b, 0x63, 0x95, 0xcc, 0x33, 0xc8, 0x56, 0x13, 0x0b, 0x1b, 0x59, 0x0f,
    0xaf, 0x3f, 0x11, 0xc8, 0xdc, 0x9f, 0x53, 0xe2, 0x9e, 0x58, 0x74, 0xe2,
    0x37, 0xd0, 0x43, 0x8a, 0xd3, 0xf1, 0x0d, 0xe8, 0xe0, 0x0a, 0x5b, 0x17,
    0xe6, 0x12, 0x2d, 0x24, 0x6e, 0xbb, 0x3c, 0xdf, 0xc8, 0x4c, 0x74, 0xf7,
    0x68, 0x69, 0xe9, 0x51, 0x42, 0xd5, 0x02, 0x08, 0x9c, 0x3a, 0xca, 0xe5,
    0xb2, 0x6c, 0x4a, 0x22, 0x7f, 0x46, 0xbd, 0x1a, 0xe8, 0x4b, 0x04, 0x1b,
    0xd4, 0xf9, 0x4f, 0xa9, 0x55, 0xcf, 0x8d, 0x60, 0x26, 0xa4, 0x00, 0x8f,
    0x3b, 0xad, 0xde, 0x6a, 0xc6, 0x07, 0x84, 0x6a, 0xf5, 0xcc, 0x29, 0x7b,
    0x14, 0x54, 0xda, 0x6a, 0xb2, 0x01, 0xa8, 0xaa, 0xf7, 0x77, 0x3a, 0x1f,
    0x35, 0xd6, 0xe7, 0xe7, 0x60, 0x6b, 0x56, 0xc2, 0x38, 0x5f, 0xe3, 0x5d,
    0x62, 0x7b, 0xd6, 0x8b,
};
static const unsigned char rsa_probe_e[3] = {
    0x01, 0x00, 0x01,
};
static const unsigned char rsa_probe_d[256] = {
    0x49, 0x5a, 0x52, 0x75, 0x62, 0xdd, 0xcd, 0x93, 0x03, 0x50, 0x9c, 0x5d,
    0x03, 0xc2, 0x98, 0xe6, 0x19, 0x8c, 0xbd, 0xd2, 0x9d, 0x89, 0x68, 0x95,
    0xb9, 0xe0, 0x7e, 0xda, 0xd2, 0x40, 0x6b, 0x79, 0x2c, 0xc1, 0x1b, 0x5c,
    0xef, 0x05, 0x37, 0xce, 0x82, 0xe1, 0x47, 0xf2, 0x25, 0x38, 0xe1, 0x2c,
    0x0c, 0x7f, 0x07, 0xfa, 0x63, 0x01, 0x99, 0xed, 0xf6, 0x2a, 0x36, 0x5b,
    0xb9, 0x0f, 0x1d, 0x95, 0x91, 0x49, 0xe0, 0x3d, 0x9e, 0x6f, 0xd1, 0xe7,
    0xd2, 0x0d, 0x7b, 0x08, 0x6b, 0x51, 0x8e, 0x72, 0x75, 0x67, 0x62, 0x08,
    0x4f, 0xc4, 0x29, 0xcc, 0xab, 0x1b, 0xaa, 0xc5, 0x63, 0x5b, 0xa0, 0xe1,
    0x87, 0x5a, 0x09, 0x9d, 0xf4, 0x1f, 0x15, 0x50, 0x62, 0xde, 0x51, 0xd2,
    0x43, 0x7a, 0x0a, 0x01, 0x73, 0x2a, 0xb6, 0xb4, 0x83, 0xb2, 0xdf, 0x6c,
    0x0a, 0x41, 0x99, 0xe2, 0xdf, 0x08, 0xb2, 0x1e, 0x46, 0xca, 0xc7, 0x12,
    0x3d, 0xe5, 0xd4, 0x64, 0x9e, 0x66, 0x07, 0x38, 0x1c, 0x47, 0xbf, 0x5a,
    0xf8, 0x23, 0x10, 0xfe, 0xe3, 0x54, 0x20, 0xf0, 0x29, 0xd3, 0x28, 0x62,
    0xd8, 0xd6, 0xaa, 0x3d, 0xcf, 0x01, 0xc2, 0x11, 0xc0, 0x20, 0x2b, 0x15,
    0x2d, 0xfa, 0x7d, 0x00, 0xbc, 0xea, 0xf8, 0x9e, 0x9c, 0x06, 0x08, 0xec,
    0x60, 0x5f, 0x17, 0x46, 0x40, 0x35, 0x87, 0xb9, 0xfb, 0x1c, 0xf5, 0xbb,
    0x3b, 0x79, 0x83, 0xa8, 0xd1, 0x78, 0xe0, 0x42, 0x42, 0x82, 0xa9, 0x4e,
    0x0d, 0xfa, 0xa1, 0xef, 0x92, 0xd5, 0x5a, 0xfd, 0x6e, 0x57, 0x79, 0x4f,
    0x70, 0x6f, 0x5b, 0xa1, 0xc2, 0x69, 0x38, 0xcf, 0x67, 0x73, 0xed, 0xf1,
    0x4d, 0x2f, 0x55, 0x29, 0x3f, 0x9d, 0x7c, 0x55, 0xf4, 0x8e, 0x9f, 0x95,
    0xbb, 0xe7, 0x4d, 0x1a, 0x25, 0x75, 0xcc, 0xaa, 0xbb, 0x4c, 0x59, 0xad,
    0xfa, 0x15, 0x4b, 0x37,
};
static const unsigned char rsa_probe_p[128] = {
    0xc3, 0x5e, 0xab, 0x24, 0x3e, 0x35, 0x4f, 0x7c, 0xf1, 0xe2, 0xbc, 0xdd,
    0x75, 0xb9, 0x67, 0x10, 0xc0, 0x13, 0x06, 0xf8, 0xd4, 0xe0, 0x6a, 0xf7,
    0xc3, 0x33, 0x4a, 0xaf, 0x97, 0xa0, 0xa4, 0x53, 0x05, 0xdc, 0x70, 0xf7,
    0x46, 0xf1, 0xb2, 0xbb, 0x09, 0xda, 0xa1, 0xbf, 0x49, 0x3e, 0x34, 0x98,
    0x57, 0x39, 0xfd, 0x8b, 0xcb, 0x74, 0x06, 0x9e, 0x41, 0xbc, 0x39, 0xc9,
    0x4c, 0xcb, 0x52, 0x84, 0x34, 0xd9, 0x6e, 0x78, 0x31, 0xe7, 0xee, 0xfb,
    0x03, 0x50, 0x1a, 0x40, 0x11, 0x6c, 0x2a, 0xb5, 0x25, 0x61, 0xed, 0x33,
    0x5f, 0x86, 0xa5, 0x19, 0xe6, 0x46, 0xde, 0x58, 0x0c, 0xec, 0x91, 0x2c,
    0xe7, 0xc2, 0x49, 0x8f, 0x95, 0x5d, 0xab, 0xe1, 0x6a, 0x8b, 0xad, 0x13,
    0x2d, 0xc6, 0x6d, 0xd3, 0x40, 0xd0, 0x7b, 0xa3, 0x6d, 0x2d, 0x50, 0x09,
    0x4b, 0x9c, 0xa2, 0xd6, 0xe8, 0xfd, 0x44, 0xbf,
};
static const unsigned char rsa_probe_q[128] = {
    0x7b, 0xf7, 0x2b, 0xba, 0x9e, 0x09, 0x6b, 0x4c, 0xef, 0x60, 0xfb, 0x6f,
    0x69, 0xd7, 0x8f, 0x4d, 0xe2, 0x80, 0x2f, 0x01, 0x17, 0xce, 0x09, 0x53,
    0x1a, 0x59, 0x26, 0xaa, 0x01, 0x2b, 0x42, 0x6d, 0xb6, 0x17, 0x87, 0x2c,
    0x45, 0x46, 0x7a, 0x02, 0xda, 0x74, 0x4c, 0xdb, 0x37, 0x8a, 0x9e, 0xcd,
    0x22, 0xa3, 0x7a, 0x58, 0x8b, 0x78, 0x3a, 0x84, 0x7a, 0x8a, 0x80, 0x57,
    0xe0, 0x94, 0x3c, 0x0a, 0xa0, 0x14, 0x28, 0x6d, 0xff, 0x1f, 0x53, 0x7c,
    0xdd, 0x27, 0xd8, 0xf2, 0x9b, 0x15, 0x72, 0x9e, 0xa2, 0xfc, 0x86, 0x7d,
    0x88, 0xc4, 0xf4, 0x55, 0x16, 0xaa, 0x36, 0xe7, 0x0d, 0xd9, 0x33, 0x13,
    0xde, 0x74, 0xe8, 0x97, 0x71, 0xef, 0xd9, 0xa8, 0x08, 0x72, 0xe5, 0x5c,
    0xaa, 0xb6, 0x0b, 0x10, 0xb3, 0xb4, 0x67, 0x33, 0x7c, 0x1a, 0xc6, 0x73,
    0x5a, 0x1d, 0xd3, 0x88, 0x12, 0x9b, 0x29, 0xbb,
};
static const unsigned char rsa_probe_dmp1[128] = {
    0xab, 0x0b, 0x0e, 0xaf, 0x2c, 0xf9, 0x81, 0x07, 0x04, 0xed, 0x44, 0x72,
    0xcf, 0xb0, 0x25, 0x94, 0xb6, 0xd9, 0x96, 0x20, 0xcd, 0x8d, 0x17, 0x28,
    0xc4, 0x96, 0x7d, 0x0d, 0xff, 0xd0, 0x8f, 0xf8, 0x79, 0xe2, 0x12, 0x6b,
    0x2a, 0xfc, 0xc2, 0x89, 0x34, 0x50, 0x61, 0xa1, 0x8a, 0xab, 0x38, 0x71,
    0x02, 0x13, 0xf9, 0xb4, 0xfa, 0x87, 0x62, 0x7a, 0x50, 0xe2, 0xd4, 0x80,
    0x1e, 0x0e, 0x79, 0x28, 0xa5, 0x47, 0xc5, 0x9b, 0x52, 0xe8, 0xa7, 0xda,
    0x68, 0x6f, 0x27, 0x38, 0xe6, 0x9d, 0x22, 0xfe, 0xcb, 0x2e, 0x20, 0x83,
    0x4c, 0xfe, 0xd9, 0xac, 0x61, 0x0c, 0xcf, 0x82, 0x31, 0xb3, 0xe2, 0xa7,
    0x81, 0x34, 0xd5, 0x9e, 0xde, 0x34, 0x58, 0x66, 0xe9, 0xf3, 0x14, 0x73,
    0x83, 0x94, 0xb2, 0xee, 0x30, 0x3a, 0xc9, 0x6e, 0x63, 0x27, 0xdd, 0x35,
    0xf3, 0x9b, 0xd4, 0xac, 0x3a, 0x5f, 0xe6, 0x52,
};
static const unsigned char rsa_probe_dmq1[128] = {
    0x49, 0xa9, 0x68, 0x82, 0xdf, 0x97, 0x66, 0x22, 0xf1, 0x80, 0x0d, 0xf2,
    0x46, 0xf8, 0xc3, 0x88, 0x41, 0x22, 0x35, 0xf8, 0xcd, 0xd3, 0xe0, 0xa9,
    0x3e, 0xc5, 0x55, 0x5a, 0xd4, 0xf5, 0x7c, 0x5f, 0x60, 0xdf, 0x99, 0x52,
    0xd5, 0xd5, 0x6e, 0xf2, 0x94, 0x27, 0x08, 0x25, 0x12, 0x32, 0x56, 0xa0,
    0x70, 0x8f, 0x0f, 0x5f, 0xf9, 0x60, 0x52, 0x8b, 0xca, 0xfb, 0x26, 0x6f,
    0xe9, 0x51, 0x65, 0x5f, 0x33, 0x5e, 0x31, 0xfa, 0xb2, 0x3c, 0xd7, 0x55,
    0x32, 0x9b, 0x86, 0xaa, 0x9c, 0x7d, 0xcd, 0xe6, 0x7c, 0x3f, 0x02, 0x99,
    0x1c, 0x2b, 0x4c, 0x35, 0x77, 0xf1, 0xae, 0xf1, 0x51, 0x4e, 0xda, 0x1d,
    0x4d, 0x02, 0x02, 0x25, 0xd3, 0xb4, 0xb6, 0xeb, 0xf9, 0x0b, 0x90, 0xdf,
    0xb7, 0x69, 0x35, 0xab, 0xe3, 0x0a, 0xbf, 0xb2, 0x08, 0xeb, 0xde, 0xd1,
    0x8c, 0x5a, 0xac, 0x60, 0x9a, 0x15, 0x2e, 0x5d,
};
static const unsigned char rsa_probe_iqmp[128] = {
    0xf9, 0x08, 0xeb, 0x84, 0x92, 0xa0, 0xc7, 0x78, 0x8c, 0x4b, 0xb6, 0xca,
    0x6b, 0x6a, 0x27, 0x61, 0x7d, 0xb0, 0xaa, 0x38, 0x2f, 0xdc, 0xee, 0x02,
    0x38, 0xc8, 0x1b, 0x76, 0xf6, 0xb3, 0x72, 0xb4, 0xd3, 0x3b, 0xf4, 0x35,
    0xd9, 0xe3, 0x87, 0xd6, 0xd4, 0x08, 0x2b, 0xfd, 0x89, 0xa2, 0x94, 0x2c,
    0xbf, 0xc8, 0x95, 0x38, 0x0d, 0x2d, 0xc2, 0x92, 0x35, 0x4b, 0xc1, 0xca,
    0xf5, 0x00, 0x91, 0x69, 0x5b, 0x00, 0x1c, 0xb9, 0xdb, 0x9a, 0xad, 0x8e,
    0xbe, 0xcb, 0x42, 0x9c, 0x63, 0x1b, 0x75, 0xee, 0xd3, 0x37, 0xe4, 0xae,
    0xa8, 0x03, 0x02, 0x80, 0xca, 0x54, 0x7d, 0x02, 0x45, 0x36, 0xef, 0x9e,
    0xd6, 0xb9, 0xd0, 0xf6, 0xb2, 0x8e, 0xb8, 0x95, 0x25, 0x40, 0xfa, 0x1d,
    0xbe, 0x30, 0x21, 0x97, 0x80, 0x03, 0xec, 0x4f, 0xd6, 0xd1, 0x83, 0x84,
    0x4e, 0x76, 0x75, 0x18, 0xcc, 0x02, 0x05, 0x31,
};

/* The fixed plaintext both encryption faces are driven with. It is shorter than the modulus by
 * more than any padding's overhead, so the same constant works for PKCS#1 v1.5 and OAEP. */
static const char asym_message[] = "openssl-rs RT-ASYM-CIPHER";

/* The fixed OAEP label. A label is *not* part of the padding's randomness, so it is the parameter
 * whose round trip a reader can check by eye; the probe prints it back in both directions. */
static const unsigned char asym_label[8] = { 0x52, 0x54, 0x2d, 0x41, 0x53, 0x59, 0x4d, 0x00 };

static EVP_PKEY *rsa_build_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    OSSL_PARAM params[9];
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;

    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, (unsigned char *)rsa_probe_n,
                                        sizeof(rsa_probe_n));
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, (unsigned char *)rsa_probe_e,
                                        sizeof(rsa_probe_e));
    params[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, (unsigned char *)rsa_probe_d,
                                        sizeof(rsa_probe_d));
    params[3] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, (unsigned char *)rsa_probe_p,
                                        sizeof(rsa_probe_p));
    params[4] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, (unsigned char *)rsa_probe_q,
                                        sizeof(rsa_probe_q));
    params[5] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                        (unsigned char *)rsa_probe_dmp1, sizeof(rsa_probe_dmp1));
    params[6] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                        (unsigned char *)rsa_probe_dmq1, sizeof(rsa_probe_dmq1));
    params[7] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                        (unsigned char *)rsa_probe_iqmp, sizeof(rsa_probe_iqmp));
    params[8] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata_init(ctx) > 0)
        (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* `n` and `n-1` as `BN_bin2bn` reads a buffer: big-endian. The authority-read modulus is in
 * `OSSL_PARAM_construct_BN`'s native order, so the reversal is what makes the degenerate-ciphertext
 * arms' two inputs *derive* from the authority's value rather than repeat it. */
static void be_n(unsigned char *out)
{
    size_t i;

    for (i = 0; i < sizeof(rsa_probe_n); i++)
        out[i] = rsa_probe_n[sizeof(rsa_probe_n) - 1 - i];
}

static void be_sub_one(unsigned char *buf, size_t len)
{
    size_t i = len;

    while (i > 0) {
        i--;
        if (buf[i] == 0) {
            buf[i] = 0xff;
        } else {
            buf[i]--;
            break;
        }
    }
}

/* The encrypt/decrypt round trip every padding mode is driven with: init with the mode's own
 * parameters, the size query, the encryption, the parameter read-back the caller supplies, the
 * decryption, and the verdict. `params` is `NULL` for the init-time default. */
static void asym_roundtrip(const char *tag, EVP_PKEY *pkey, OSSL_PARAM *params,
                           const unsigned char *in, size_t inlen)
{
    unsigned char ct[512];
    unsigned char pt[512];
    size_t ctlen;
    size_t ptlen;
    EVP_PKEY_CTX *ctx;
    char key[160];
    int encrypt_ok;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    snprintf(key, sizeof(key), "%s.encrypt_init", tag);
    kv_int(key, EVP_PKEY_encrypt_init_ex(ctx, params));

    ctlen = sizeof(ct);
    snprintf(key, sizeof(key), "%s.size", tag);
    kv_int(key, EVP_PKEY_encrypt(ctx, NULL, &ctlen, NULL, 0));
    snprintf(key, sizeof(key), "%s.size_len", tag);
    kv_int(key, (int)ctlen);

    ctlen = sizeof(ct);
    snprintf(key, sizeof(key), "%s.encrypt", tag);
    encrypt_ok = EVP_PKEY_encrypt(ctx, ct, &ctlen, in, inlen);
    kv_int(key, encrypt_ok);
    snprintf(key, sizeof(key), "%s.ct_len", tag);
    kv_int(key, (int)ctlen);
    EVP_PKEY_CTX_free(ctx);

    if (encrypt_ok <= 0)
        return;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    snprintf(key, sizeof(key), "%s.decrypt_init", tag);
    kv_int(key, EVP_PKEY_decrypt_init_ex(ctx, params));

    ptlen = sizeof(pt);
    snprintf(key, sizeof(key), "%s.decrypt", tag);
    kv_int(key, EVP_PKEY_decrypt(ctx, pt, &ptlen, ct, ctlen));
    snprintf(key, sizeof(key), "%s.pt_len", tag);
    kv_int(key, (int)ptlen);
    snprintf(key, sizeof(key), "%s.roundtrip", tag);
    kv_int(key, ptlen == inlen && memcmp(pt, in, inlen) == 0);
    EVP_PKEY_CTX_free(ctx);
}

/* The parameters a mode is read back with: the pad mode as the *name* the row selects a
 * `RSA_METHOD` member with, plus the mode-specific ones. */
static void asym_read_params(const char *tag, EVP_PKEY_CTX *ctx)
{
    char pad[32] = { 0 };
    char digest[32] = { 0 };
    char mgf1[32] = { 0 };
    void *label = NULL;
    unsigned int imrej = 0xffffffff;
    OSSL_PARAM gp[6];
    char key[160];

    gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, pad, sizeof(pad));
    gp[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, digest,
                                             sizeof(digest));
    gp[2] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1,
                                             sizeof(mgf1));
    gp[3] = OSSL_PARAM_construct_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, &label, 0);
    gp[4] = OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, &imrej);
    gp[5] = OSSL_PARAM_construct_end();

    snprintf(key, sizeof(key), "%s.get", tag);
    kv_int(key, ctx != NULL && EVP_PKEY_CTX_get_params(ctx, gp) > 0);
    snprintf(key, sizeof(key), "%s.pad_mode", tag);
    kv_str(key, pad);
    snprintf(key, sizeof(key), "%s.oaep_digest", tag);
    kv_str(key, digest);
    snprintf(key, sizeof(key), "%s.mgf1_digest", tag);
    kv_str(key, mgf1);
    snprintf(key, sizeof(key), "%s.implicit_rejection", tag);
    kv_int(key, (int)imrej);
    if (label != NULL && gp[3].return_size > 0) {
        snprintf(key, sizeof(key), "%s.oaep_label", tag);
        kv_hex(key, label, gp[3].return_size);
    }
}

int main(void)
{
    EVP_PKEY *pkey;
    EVP_ASYM_CIPHER *cipher_row;
    EVP_KEM *kem_row;
    unsigned char none_in[256];
    unsigned char ct[512];
    size_t ctlen;
    size_t i;

    /* The warm-up: every arm below reaches the default provider, and a process that has not yet
     * touched it answers 0 from the first `EVP_MD_fetch` a padding mode's default digest needs.
     * One `RAND_bytes` call loads it for all of them, so a refusal the probe measures is the row's
     * and not the loader's. The byte is not printed and does not reach the transcript. */
    {
        unsigned char warm = 0;

        (void)RAND_bytes(&warm, 1);
    }

    /* The two rows, fetched by name. */
    cipher_row = EVP_ASYM_CIPHER_fetch(NULL, "RSA", NULL);
    kv_int("asym.RSA.fetch", cipher_row != NULL);
    EVP_ASYM_CIPHER_free(cipher_row);

    kem_row = EVP_KEM_fetch(NULL, "RSA", NULL);
    kv_int("kem.RSA.fetch", kem_row != NULL);
    EVP_KEM_free(kem_row);

    pkey = rsa_build_key();
    kv_int("asym.RSA.key", pkey != NULL);
    if (pkey == NULL)
        return 0;

    /* 1. PKCS#1 v1.5, the mode `rsa_init` seeds: the size query, the encryption, the read-back,
     *    the decryption and the round trip. */
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);

        asym_roundtrip("asym.RSA.pkcs1", pkey, NULL, (const unsigned char *)asym_message,
                       sizeof(asym_message) - 1);
        if (ctx != NULL && EVP_PKEY_encrypt_init_ex(ctx, NULL) > 0)
            asym_read_params("asym.RSA.pkcs1", ctx);
        EVP_PKEY_CTX_free(ctx);
    }

    /* 2. OAEP with SHA-256 for both the digest and MGF1 and a fixed label: the round trip, then the
     *    read-back of all three parameters. OAEP is randomised, so the ciphertext is not printed. */
    {
        OSSL_PARAM params[5];
        EVP_PKEY_CTX *ctx;

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                     (char *)"oaep", 0);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                                     (char *)"SHA256", 0);
        params[2] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                                     (char *)"SHA256", 0);
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                                      (void *)asym_label, sizeof(asym_label));
        params[4] = OSSL_PARAM_construct_end();

        asym_roundtrip("asym.RSA.oaep", pkey, params, (const unsigned char *)asym_message,
                       sizeof(asym_message) - 1);

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_encrypt_init_ex(ctx, params) > 0)
            asym_read_params("asym.RSA.oaep", ctx);
        EVP_PKEY_CTX_free(ctx);
    }

    /* 3. `none`: the only *deterministic* arm. `RSAEP` with no padding is `m^e mod n`, and the input
     *    is a fixed 256-byte string whose most significant byte is below the modulus's, so the
     *    ciphertext is the same on both sides and is printed in full. This is the arm that notices a
     *    wrong `n`, `e` or `OSSL_PARAM_construct_BN` byte order. */
    for (i = 0; i < sizeof(none_in); i++)
        none_in[i] = (unsigned char)(i + 1);
    none_in[sizeof(none_in) - 1] = 0x01; /* below the modulus's 0x8b top byte */

    {
        OSSL_PARAM params[2];
        int pad_mode = RSA_NO_PADDING;
        EVP_PKEY_CTX *ctx;

        params[0] = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &pad_mode);
        params[1] = OSSL_PARAM_construct_end();

        asym_roundtrip("asym.RSA.none", pkey, params, none_in, sizeof(none_in));

        /* The same encryption once more, so its ciphertext can be printed: the round trip above
         * deliberately does not print it, and this is the one mode where printing it is a
         * measurement rather than a coin flip. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_encrypt_init_ex(ctx, params) > 0) {
            ctlen = sizeof(ct);
            if (EVP_PKEY_encrypt(ctx, ct, &ctlen, none_in, sizeof(none_in)) > 0)
                kv_hex("asym.RSA.none.ct", ct, ctlen);
        }
        EVP_PKEY_CTX_free(ctx);
    }

    /* 4. The two refusals a caller can reach with a fixed input: a one-byte destination in each
     *    direction, and an input the `none` mode cannot accept because its length is not the
     *    modulus's. */
    {
        unsigned char one[1];
        size_t one_len = 1;

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);

        if (ctx != NULL && EVP_PKEY_encrypt_init_ex(ctx, NULL) > 0)
            kv_int("asym.RSA.encrypt_small_buffer",
                   EVP_PKEY_encrypt(ctx, one, &one_len, (const unsigned char *)asym_message,
                                    sizeof(asym_message) - 1));
        drain("asym.RSA.encrypt_small_buffer");
        EVP_PKEY_CTX_free(ctx);

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_encrypt_init_ex(ctx, NULL) > 0) {
            ctlen = sizeof(ct);
            if (EVP_PKEY_encrypt(ctx, ct, &ctlen, (const unsigned char *)asym_message,
                                 sizeof(asym_message) - 1) > 0) {
                one_len = 1;
                kv_int("asym.RSA.decrypt_small_buffer",
                       EVP_PKEY_decrypt(ctx, one, &one_len, ct, ctlen));
                drain("asym.RSA.decrypt_small_buffer");
            }
        }
        EVP_PKEY_CTX_free(ctx);

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL) {
            int pad_mode = RSA_NO_PADDING;
            OSSL_PARAM params[2];

            params[0] = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &pad_mode);
            params[1] = OSSL_PARAM_construct_end();
            if (EVP_PKEY_encrypt_init_ex(ctx, params) > 0) {
                ctlen = sizeof(ct);
                kv_int("asym.RSA.none_short_input",
                       EVP_PKEY_encrypt(ctx, ct, &ctlen, (const unsigned char *)asym_message,
                                        sizeof(asym_message) - 1));
                drain("asym.RSA.none_short_input");
            }
        }
        EVP_PKEY_CTX_free(ctx);
    }

    /* 5. The legacy numeric pad-mode parameter, and the two `pss` paths. The name table holds no
     *    `pss` entry, so the *name* is not refused: the lookup fails, `pad_mode` becomes 0, and the
     *    mode the row then carries is the one `RSA_public_encrypt` answers -1 for. The *number* 6 is
     *    refused -- that is the arm the setter's comment is about. Printing both is what pins the
     *    table's contents rather than the setter's intent. */
    {
        int pad_mode = RSA_PKCS1_PADDING;
        int pss_number = RSA_PKCS1_PSS_PADDING;
        OSSL_PARAM numeric[2];
        OSSL_PARAM pss_name[2];
        OSSL_PARAM pss_num[2];
        EVP_PKEY_CTX *ctx;

        numeric[0] = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &pad_mode);
        numeric[1] = OSSL_PARAM_construct_end();
        pss_name[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                       (char *)"pss", 0);
        pss_name[1] = OSSL_PARAM_construct_end();
        pss_num[0] = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &pss_number);
        pss_num[1] = OSSL_PARAM_construct_end();

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL) {
            kv_int("asym.RSA.numeric_init", EVP_PKEY_encrypt_init_ex(ctx, numeric));
            /* The number was accepted; the *name* it maps back to is the read-back that proves the
             * table is walked in both directions. */
            asym_read_params("asym.RSA.numeric", ctx);
            kv_int("asym.RSA.pss_name", EVP_PKEY_CTX_set_params(ctx, pss_name));
            ctlen = sizeof(ct);
            kv_int("asym.RSA.pss_name_encrypt",
                   EVP_PKEY_encrypt(ctx, ct, &ctlen, (const unsigned char *)asym_message,
                                    sizeof(asym_message) - 1));
            drain("asym.RSA.pss_name_encrypt");
        }
        EVP_PKEY_CTX_free(ctx);

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_encrypt_init_ex(ctx, NULL) > 0)
            kv_int("asym.RSA.pss_number", EVP_PKEY_CTX_set_params(ctx, pss_num));
        EVP_PKEY_CTX_free(ctx);
    }

    /* 6. `RSA_PKCS1_WITH_TLS_PADDING`, whose number is read from `include/openssl/rsa.h` rather than
     *    typed. The mode has no `RSA_METHOD` member, so its whole observable contract is the size
     *    query (the master-secret length) and the `client_version == 0` refusal. The ciphertext it
     *    is handed is a `none`-mode one, so the arm does not depend on an earlier arm's buffer. */
    {
        int tls_mode = RSA_PKCS1_WITH_TLS_PADDING;
        int none_mode = RSA_NO_PADDING;
        unsigned int client_version = 0x0303u;
        OSSL_PARAM params[2];
        OSSL_PARAM version[2];
        unsigned char tls_ct[512];
        size_t tls_ctlen = sizeof(tls_ct);
        unsigned char out[512];
        size_t outlen = sizeof(out);
        EVP_PKEY_CTX *ctx;

        params[0] = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &tls_mode);
        params[1] = OSSL_PARAM_construct_end();
        version[0] = OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
                                               &client_version);
        version[1] = OSSL_PARAM_construct_end();

        /* The ciphertext: `none` mode, so it is `RSAEP(m)` and independent of every other arm. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL) {
            int none = none_mode;
            OSSL_PARAM none_params[2];

            none_params[0] = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &none);
            none_params[1] = OSSL_PARAM_construct_end();
            if (EVP_PKEY_encrypt_init_ex(ctx, none_params) > 0)
                (void)EVP_PKEY_encrypt(ctx, tls_ct, &tls_ctlen, none_in, sizeof(none_in));
        }
        EVP_PKEY_CTX_free(ctx);

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_decrypt_init_ex(ctx, params) > 0) {
            /* The size query: the mode answers the master-secret length, not the modulus's. */
            kv_int("asym.RSA.tls.size", EVP_PKEY_decrypt(ctx, NULL, &outlen, NULL, 0));
            kv_int("asym.RSA.tls.size_len", (int)outlen);

            /* The `client_version == 0` refusal, which is the mode's own gate. */
            outlen = sizeof(out);
            kv_int("asym.RSA.tls.no_version",
                   EVP_PKEY_decrypt(ctx, out, &outlen, tls_ct, tls_ctlen));
            drain("asym.RSA.tls.no_version");

            /* With a version set the gate is passed and the constant-time padding check runs. Its
             * *verdict* is always 48 bytes -- that is the check's whole design -- so what is
             * observed is the return code and the record count, which is zero because a successful
             * check raises nothing. */
            kv_int("asym.RSA.tls.set_version", EVP_PKEY_CTX_set_params(ctx, version));
            outlen = sizeof(out);
            kv_int("asym.RSA.tls.checked",
                   EVP_PKEY_decrypt(ctx, out, &outlen, tls_ct, tls_ctlen));
            drain("asym.RSA.tls.checked");
        }
        EVP_PKEY_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);

    /* ----------------------------------------------------------------------------------------- */
    /* The `OSSL_OP_KEM` RSA row: RSASVE.                                                         */
    /* ----------------------------------------------------------------------------------------- */

    pkey = rsa_build_key();
    kv_int("kem.RSA.key", pkey != NULL);
    if (pkey == NULL)
        return 0;

    {
        unsigned char secret[512];
        unsigned char recovered[512];
        size_t secretlen;
        size_t recoveredlen;
        EVP_PKEY_CTX *ctx;

        /* 1. The round trip: the size query, the encapsulation, the decapsulation and the verdict
         *    that the recovered secret is the one the encapsulation published. The secret itself is
         *    not printed -- it is random -- but the verdict is the same on both sides. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        kv_int("kem.RSA.encapsulate_init", EVP_PKEY_encapsulate_init(ctx, NULL));
        ctlen = sizeof(ct);
        secretlen = sizeof(secret);
        kv_int("kem.RSA.size", EVP_PKEY_encapsulate(ctx, NULL, &ctlen, NULL, &secretlen));
        kv_int("kem.RSA.size_ct", (int)ctlen);
        kv_int("kem.RSA.size_secret", (int)secretlen);
        ctlen = sizeof(ct);
        secretlen = sizeof(secret);
        kv_int("kem.RSA.encapsulate",
               EVP_PKEY_encapsulate(ctx, ct, &ctlen, secret, &secretlen));
        kv_int("kem.RSA.ct_len", (int)ctlen);
        kv_int("kem.RSA.secret_len", (int)secretlen);
        EVP_PKEY_CTX_free(ctx);

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        kv_int("kem.RSA.decapsulate_init", EVP_PKEY_decapsulate_init(ctx, NULL));
        recoveredlen = sizeof(recovered);
        kv_int("kem.RSA.decapsulate",
               EVP_PKEY_decapsulate(ctx, recovered, &recoveredlen, ct, ctlen));
        kv_int("kem.RSA.recovered_len", (int)recoveredlen);
        kv_int("kem.RSA.roundtrip",
               recoveredlen == secretlen && memcmp(recovered, secret, secretlen) == 0);
        EVP_PKEY_CTX_free(ctx);

        /* 2. The size refusal: an output buffer shorter than `n`. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_encapsulate_init(ctx, NULL) > 0) {
            unsigned char small[16];
            size_t smalllen = sizeof(small);
            size_t slen = sizeof(secret);

            kv_int("kem.RSA.small_buffer",
                   EVP_PKEY_encapsulate(ctx, small, &smalllen, secret, &slen));
            drain("kem.RSA.small_buffer");
        }
        EVP_PKEY_CTX_free(ctx);

        /* 3. The length refusal: a ciphertext that is not `n` bytes. */
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_decapsulate_init(ctx, NULL) > 0) {
            recoveredlen = sizeof(recovered);
            kv_int("kem.RSA.short_input",
                   EVP_PKEY_decapsulate(ctx, recovered, &recoveredlen, ct, ctlen / 2));
            drain("kem.RSA.short_input");
        }
        EVP_PKEY_CTX_free(ctx);
    }

    /* 4. The `operation` parameter: `RSASVE` is the only name the row's map holds, and any other
     *    answers 0 from `rsakem_set_ctx_params`. */
    {
        OSSL_PARAM ok[2];
        OSSL_PARAM bad[2];
        EVP_PKEY_CTX *ctx;

        ok[0] = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                                 (char *)OSSL_KEM_PARAM_OPERATION_RSASVE, 0);
        ok[1] = OSSL_PARAM_construct_end();
        bad[0] = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                                  (char *)"NOSUCH", 0);
        bad[1] = OSSL_PARAM_construct_end();

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        kv_int("kem.RSA.operation_rsasve", EVP_PKEY_encapsulate_init(ctx, ok));
        EVP_PKEY_CTX_free(ctx);

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        kv_int("kem.RSA.operation_unknown", EVP_PKEY_encapsulate_init(ctx, bad));
        drain("kem.RSA.operation_unknown");
        EVP_PKEY_CTX_free(ctx);
    }

    /* 5. The degenerate ciphertexts. RSADP's own `1 < c < n-1` bound is the FIPS arm's; the
     *    non-FIPS build enforces it in `rsasve_recover` and raises the primitive's own reasons, so
     *    the drain is what shows *which* reason each input produced. `n` and `n-1` are derived from
     *    the authority-read modulus, big-endian. */
    {
        unsigned char bad[256];
        unsigned char recovered[512];
        size_t recoveredlen;
        EVP_PKEY_CTX *ctx;

        /* c = 0 */
        memset(bad, 0, sizeof(bad));
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_decapsulate_init(ctx, NULL) > 0) {
            recoveredlen = sizeof(recovered);
            kv_int("kem.RSA.c_zero",
                   EVP_PKEY_decapsulate(ctx, recovered, &recoveredlen, bad, sizeof(bad)));
            drain("kem.RSA.c_zero");
        }
        EVP_PKEY_CTX_free(ctx);

        /* c = 1 */
        memset(bad, 0, sizeof(bad));
        bad[sizeof(bad) - 1] = 0x01;
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_decapsulate_init(ctx, NULL) > 0) {
            recoveredlen = sizeof(recovered);
            kv_int("kem.RSA.c_one",
                   EVP_PKEY_decapsulate(ctx, recovered, &recoveredlen, bad, sizeof(bad)));
            drain("kem.RSA.c_one");
        }
        EVP_PKEY_CTX_free(ctx);

        /* c = n-1 */
        be_n(bad);
        be_sub_one(bad, sizeof(bad));
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_decapsulate_init(ctx, NULL) > 0) {
            recoveredlen = sizeof(recovered);
            kv_int("kem.RSA.c_n_minus_1",
                   EVP_PKEY_decapsulate(ctx, recovered, &recoveredlen, bad, sizeof(bad)));
            drain("kem.RSA.c_n_minus_1");
        }
        EVP_PKEY_CTX_free(ctx);

        /* c = n */
        be_n(bad);
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (ctx != NULL && EVP_PKEY_decapsulate_init(ctx, NULL) > 0) {
            recoveredlen = sizeof(recovered);
            kv_int("kem.RSA.c_n",
                   EVP_PKEY_decapsulate(ctx, recovered, &recoveredlen, bad, sizeof(bad)));
            drain("kem.RSA.c_n");
        }
        EVP_PKEY_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);

    /* ----------------------------------------------------------------------------------------- */
    /* The `OSSL_OP_ASYM_CIPHER` SM2 row (D406).                                                  */
    /* ----------------------------------------------------------------------------------------- */

    /* The row by name, then a key generated through the `SM2` keymgmt row and an encrypt/decrypt
     * round trip. The published GM/T 0003.5-2012 known answers are the crypt unit's own unit tests
     * (`src/sm2/crypt.rs`); here the row is driven through its dispatch and the round trip observed,
     * which is the registration-row court's subject. */
    {
        EVP_ASYM_CIPHER *sm2_row = EVP_ASYM_CIPHER_fetch(NULL, "SM2", NULL);
        EVP_PKEY_CTX *kctx;
        EVP_PKEY *skey = NULL;
        OSSL_PARAM gparams[2];

        kv_int("asym.SM2.fetch", sm2_row != NULL);
        EVP_ASYM_CIPHER_free(sm2_row);

        kctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
        gparams[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"SM2", 0);
        gparams[1] = OSSL_PARAM_construct_end();
        kv_int("asym.SM2.keygen_init", kctx != NULL && EVP_PKEY_keygen_init(kctx) > 0);
        kv_int("asym.SM2.set_group", kctx != NULL && EVP_PKEY_CTX_set_params(kctx, gparams) > 0);
        kv_int("asym.SM2.keygen", kctx != NULL && EVP_PKEY_keygen(kctx, &skey) > 0);
        EVP_PKEY_CTX_free(kctx);
        drain("asym.SM2.keygen");

        if (skey != NULL) {
            unsigned char ct[512];
            unsigned char pt[512];
            size_t ctlen;
            size_t ptlen;
            int encrypt_ok;
            EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, skey, NULL);

            /* SM2 encryption is randomised, and its DER ciphertext length varies with the two
             * INTEGER components' leading zeroes, so neither the ciphertext nor its length is
             * printed; the size query, the message length and the round trip are deterministic. */
            kv_int("asym.SM2.encrypt_init", c != NULL && EVP_PKEY_encrypt_init_ex(c, NULL) > 0);
            ctlen = sizeof(ct);
            kv_int("asym.SM2.size", c != NULL && EVP_PKEY_encrypt(c, NULL, &ctlen, NULL, 0) > 0);
            kv_int("asym.SM2.size_len", (int)ctlen);
            ctlen = sizeof(ct);
            encrypt_ok = c != NULL && EVP_PKEY_encrypt(c, ct, &ctlen,
                                                       (const unsigned char *)asym_message,
                                                       sizeof(asym_message) - 1) > 0;
            kv_int("asym.SM2.encrypt", encrypt_ok);
            if (c != NULL && EVP_PKEY_encrypt_init_ex(c, NULL) > 0) {
                char digest[32] = { 0 };
                OSSL_PARAM gp[2];

                gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, digest,
                                                         sizeof(digest));
                gp[1] = OSSL_PARAM_construct_end();
                kv_int("asym.SM2.get", EVP_PKEY_CTX_get_params(c, gp) > 0);
                kv_str("asym.SM2.digest", digest);
            }
            EVP_PKEY_CTX_free(c);

            if (encrypt_ok) {
                c = EVP_PKEY_CTX_new_from_pkey(NULL, skey, NULL);
                kv_int("asym.SM2.decrypt_init", c != NULL && EVP_PKEY_decrypt_init_ex(c, NULL) > 0);
                ptlen = sizeof(pt);
                kv_int("asym.SM2.decrypt",
                       c != NULL && EVP_PKEY_decrypt(c, pt, &ptlen, ct, ctlen) > 0);
                kv_int("asym.SM2.pt_len", (int)ptlen);
                kv_int("asym.SM2.roundtrip",
                       ptlen == sizeof(asym_message) - 1
                           && memcmp(pt, asym_message, sizeof(asym_message) - 1) == 0);
                EVP_PKEY_CTX_free(c);
            }
            EVP_PKEY_free(skey);
        }
    }

    ERR_clear_error();
    return 0;
}
