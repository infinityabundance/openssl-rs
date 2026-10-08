/*
 * openssl-rs — the shared header of the 24.10 hostility-augmentation probes.
 *
 * Every probe is a standalone, deterministic program compiled twice — once against the admitted
 * authority's OpenSSL install prefix, once against the candidate drop-in install — and run locally.
 * The shared banner is the **section-61 enabled-path proof**: the probe prints, at run time, the
 * version string of the subject it was built against (`OPENSSL_VERSION_TEXT` from the subject's own
 * headers), the runtime version the loaded library answers (`OpenSSL_version(OPENSSL_VERSION)`), and
 * the absolute path of the library the process actually loaded (the `dladdr` of an OpenSSL symbol).
 * A probe whose loaded library is not the subject's is a finding, not a pass.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef HOSTILITY_COMMON_H
#define HOSTILITY_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* The runtime library the process actually loaded: the dladdr of a symbol the subject exports.
 * This is the enabled-path proof (the OpenSSL path is actually this subject). */
static const char *hostility_lib_path(void)
{
    Dl_info info;
    if (dladdr((void *)&OpenSSL_version, &info) != 0 && info.dli_fname != NULL)
        return info.dli_fname;
    return "unresolved";
}

static void hostility_banner(const char *surface)
{
    printf("surface=%s\n", surface);
    printf("openssl_version_text=%s\n", OPENSSL_VERSION_TEXT);
    printf("openssl_runtime_version=%s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("openssl_lib=%s\n", hostility_lib_path());
    fflush(stdout);
}

static void hostility_fail(const char *why)
{
    printf("result=failed\n");
    printf("reason=%s\n", why);
    fflush(stdout);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void hostility_ok(void)
{
    printf("result=ok\n");
    fflush(stdout);
}

/* A fresh RSA key, generated through the subject's own keygen. */
static EVP_PKEY *hostility_keygen(int bits)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)bits);
}

/* A minimal self-signed certificate over `k`, so the PKCS#12 / CMS / TLS probes have a subject. */
static X509 *hostility_selfsigned(EVP_PKEY *k, const char *cn)
{
    X509 *x = X509_new();
    if (x == NULL)
        return NULL;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, k);
    X509_NAME *n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x, n);
    if (!X509_sign(x, k, EVP_sha256())) {
        X509_free(x);
        return NULL;
    }
    return x;
}

#endif /* HOSTILITY_COMMON_H */
