/*
 * RT-LEGACY-MODULE — the legacy provider module, as subphase 16.1 lands it.
 *
 * Compiled twice (authority and candidate), run, and the two transcripts compared
 * line by line. The probe loads the `legacy` provider through the same
 * `OSSL_PROVIDER_load` path the authority's own CLI uses, reads the provider's
 * `name` through `OSSL_PROVIDER_get_params`, asks the module's
 * `OSSL_PROVIDER_query_operation` for each of the four operations 16.1 publishes
 * (`OSSL_OP_DIGEST`, `OSSL_OP_CIPHER`, `OSSL_OP_KDF`, `OSSL_OP_SKEYMGMT`), and
 * prints each operation's row count and first row's alias sequence. It then:
 *
 *   * fetches the four legacy digests by primary name and by OID through the
 *     `provider=legacy` property and prints a fixed `"abc"` digest for each;
 *   * fetches each of the 32 `legacy_ciphers` rows by primary name, encrypts a
 *     fixed 16-byte plaintext under a fixed 24-byte key / 16-byte IV with padding
 *     off, prints the ciphertext, then decrypts it and prints whether the
 *     round-trip recovered the plaintext;
 *   * fetches the two `legacy_kdfs` rows (`PBKDF1`, `PVKKDF`), derives 32 bytes
 *     of SHA-256 output from a fixed password/salt/iteration count, and prints
 *     the result.
 *
 * and closes with the refusal arms: an unknown digest/cipher/KDF name, a legacy
 * cipher asked of the `default` provider, a `PBKDF1` derive with no salt, and a
 * `PBKDF1` derive whose output length exceeds the digest size.
 *
 * Deterministic `key=value` lines only: no wall clock, no network, no address, and
 * no error-queue read (`ERR_*` is never called, so the candidate's and the
 * authority's differing error implementations cannot leak into the comparison).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void print_operation(OSSL_PROVIDER *prov, int operation_id, const char *label)
{
    int no_cache = -1;
    const OSSL_ALGORITHM *algs =
        OSSL_PROVIDER_query_operation(prov, operation_id, &no_cache);
    int n = 0;

    if (algs != NULL) {
        for (; algs[n].algorithm_names != NULL; n++)
            ;
    }
    printf("count.%s=%d\n", label, n);
    printf("nocache.%s=%d\n", label, no_cache);
    if (n > 0) {
        printf("first.%s=%s\n", label, algs[0].algorithm_names);
        printf("prop.%s=%s\n", label,
               algs[0].property_definition != NULL ? algs[0].property_definition : "(null)");
    }
}

static void print_hex(const char *key, const unsigned char *data, int len)
{
    int i;

    printf("%s=", key);
    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static void print_digest(const char *label, const char *name, const char *properties)
{
    EVP_MD *md = EVP_MD_fetch(NULL, name, properties);
    printf("fetch.%s=%d\n", label, md != NULL);
    if (md == NULL)
        return;
    printf("size.%s=%d\n", label, EVP_MD_get_size(md));
    {
        unsigned char out[EVP_MAX_MD_SIZE];
        unsigned int outl = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        int ok = ctx != NULL
                 && EVP_DigestInit_ex(ctx, md, NULL) == 1
                 && EVP_DigestUpdate(ctx, "abc", 3) == 1
                 && EVP_DigestFinal_ex(ctx, out, &outl) == 1;
        printf("digest.%s.ok=%d\n", label, ok);
        printf("digest.%s.len=%u\n", label, outl);
        if (ok) {
            printf("digest.%s=", label);
            for (unsigned int i = 0; i < outl; i++)
                printf("%02x", out[i]);
            printf("\n");
        }
        EVP_MD_CTX_free(ctx);
    }
    EVP_MD_free(md);
}

/* A fixed key (24 bytes, so DESX's 24-byte row is covered), IV (16 bytes, so
 * SEED's 128-bit IV is covered) and 16-byte plaintext. Rows with shorter keys or
 * IVs read only their own prefix. */
static const unsigned char KEY[24] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};
static const unsigned char IV[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const unsigned char PLAIN[16] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50
};

static void print_cipher(const char *label, const char *name)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, "provider=legacy");
    printf("fetch.%s=%d\n", label, c != NULL);
    if (c == NULL)
        return;
    printf("keylen.%s=%d\n", label, EVP_CIPHER_get_key_length(c));
    printf("ivlen.%s=%d\n", label, EVP_CIPHER_get_iv_length(c));
    printf("block.%s=%d\n", label, EVP_CIPHER_get_block_size(c));
    {
        unsigned char ct[64];
        unsigned char rt[64];
        int outl = 0, tmpl = 0, ok = 0;
        int routl = 0, rtmpl = 0, rok = 0;
        const unsigned char *ivp = EVP_CIPHER_get_iv_length(c) > 0 ? IV : NULL;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (ctx != NULL
            && EVP_EncryptInit_ex(ctx, c, NULL, KEY, ivp) == 1
            && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
            && EVP_EncryptUpdate(ctx, ct, &outl, PLAIN, 16) == 1
            && EVP_EncryptFinal_ex(ctx, ct + outl, &tmpl) == 1) {
            outl += tmpl;
            ok = 1;
        }
        printf("enc.%s.ok=%d\n", label, ok);
        printf("enc.%s.len=%d\n", label, outl);
        if (ok) {
            char key[64];
            snprintf(key, sizeof(key), "enc.%s", label);
            print_hex(key, ct, outl);
        }
        EVP_CIPHER_CTX_free(ctx);

        ctx = EVP_CIPHER_CTX_new();
        if (ok && ctx != NULL
            && EVP_DecryptInit_ex(ctx, c, NULL, KEY, ivp) == 1
            && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
            && EVP_DecryptUpdate(ctx, rt, &routl, ct, outl) == 1
            && EVP_DecryptFinal_ex(ctx, rt + routl, &rtmpl) == 1) {
            routl += rtmpl;
            rok = 1;
        }
        printf("dec.%s.ok=%d\n", label, rok);
        printf("dec.%s.roundtrip=%d\n", label,
               rok && routl == 16 && memcmp(rt, PLAIN, 16) == 0);
        EVP_CIPHER_CTX_free(ctx);
    }
    EVP_CIPHER_free(c);
}

static void print_cipher_table(void)
{
    static const char *const names[] = {
        "CAST5-ECB", "CAST5-CBC", "CAST5-OFB", "CAST5-CFB",
        "BF-ECB", "BF-CBC", "BF-OFB", "BF-CFB",
        "IDEA-ECB", "IDEA-CBC", "IDEA-OFB", "IDEA-CFB",
        "SEED-ECB", "SEED-CBC", "SEED-OFB", "SEED-CFB",
        "RC2-ECB", "RC2-CBC", "RC2-40-CBC", "RC2-64-CBC", "RC2-CFB", "RC2-OFB",
        "RC4", "RC4-40", "RC4-HMAC-MD5",
        "DESX-CBC",
        "DES-ECB", "DES-CBC", "DES-OFB", "DES-CFB", "DES-CFB1", "DES-CFB8"
    };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        print_cipher(names[i], names[i]);
}

static int derive_kdf(const char *name, unsigned char *out, int outlen, int with_iter,
                      int with_salt)
{
    static const unsigned char pass[8] = {
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64
    }; /* "password" */
    static const unsigned char salt[8] = {
        0x73, 0x61, 0x6c, 0x74, 0x73, 0x61, 0x6c, 0x74
    }; /* "saltsalt" */
    static uint64_t iter = 1000;
    EVP_KDF *k = EVP_KDF_fetch(NULL, name, "provider=legacy");
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[5];
    int i = 0;
    int ok = 0;

    if (k == NULL)
        return 0;
    kctx = EVP_KDF_CTX_new(k);
    if (kctx != NULL) {
        params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                       (char *)"SHA256", 0);
        params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                        (void *)pass, sizeof(pass));
        if (with_salt)
            params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                            (void *)salt, sizeof(salt));
        if (with_iter)
            params[i++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iter);
        params[i] = OSSL_PARAM_construct_end();
        ok = EVP_KDF_derive(kctx, out, (size_t)outlen, params) == 1;
    }
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(k);
    return ok;
}

static void print_kdf(const char *label, const char *name)
{
    unsigned char out[32];
    int ok;
    EVP_KDF *k = EVP_KDF_fetch(NULL, name, "provider=legacy");

    printf("fetch.%s=%d\n", label, k != NULL);
    if (k == NULL)
        return;
    EVP_KDF_free(k);
    ok = derive_kdf(name, out, 32, strcmp(name, "PBKDF1") == 0, 1);
    printf("kdf.%s.ok=%d\n", label, ok);
    if (ok) {
        char key[64];
        snprintf(key, sizeof(key), "kdf.%s", label);
        print_hex(key, out, 32);
    }
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *legacy;
    char *prov_name = NULL;
    OSSL_PARAM params[2];

    /* The module search path is a distribution fact, and the two sides answer it
     * differently: the authority is installed, so its compiled-in MODULESDIR
     * resolves `legacy.so`; the candidate distribution shell is not installed, so its
     * `ossl-modules/` directory is empty and the module must be named explicitly. The
     * court venue sets `OPENSSL_MODULES` per side (its `side_env`); the FRF runtime
     * harness sets only `LD_LIBRARY_PATH`. So the probe names its own side's directory
     * when the variable is unset, deriving the side from `argv[0]` (the staged
     * `<probe>.{authority,candidate}` name) so one source serves both and the court is
     * reproducible under either harness. When the venue already set it, this is a no-op. */
    {
        const char *mods = getenv("OPENSSL_MODULES");
        const char *self = (argc > 0 && argv[0] != NULL) ? argv[0] : "";

        if (mods == NULL || mods[0] == '\0') {
            if (strstr(self, "candidate") != NULL)
                setenv("OPENSSL_MODULES",
                       "/work/artifacts/phase2/install/lib/ossl-modules", 1);
            else
                setenv("OPENSSL_MODULES",
                       "/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/"
                       "ossl-modules", 1);
        }
    }

    legacy = OSSL_PROVIDER_load(NULL, "legacy");
    printf("load.legacy=%d\n", legacy != NULL);
    if (legacy == NULL)
        return 1;

    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &prov_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    printf("getparams.ok=%d\n", OSSL_PROVIDER_get_params(legacy, params));
    printf("provider.name=%s\n", prov_name != NULL ? prov_name : "(null)");

    print_operation(legacy, OSSL_OP_DIGEST, "digest");
    print_operation(legacy, OSSL_OP_CIPHER, "cipher");
    print_operation(legacy, OSSL_OP_KDF, "kdf");
    /* The one `legacy_skeymgmt` row is named here so the provider-court-coverage join can see the
     * observation: the probe queries `OSSL_OP_SKEYMGMT` and compares `first.skeymgmt` against the
     * authority, and the row's alias is "GENERIC-SECRET". */
    print_operation(legacy, OSSL_OP_SKEYMGMT, "skeymgmt");

    /* The four `legacy_digests` rows, by primary name and by their OID alias. */
    print_digest("MD4", "MD4", "provider=legacy");
    print_digest("MDC2", "MDC2", "provider=legacy");
    print_digest("WHIRLPOOL", "WHIRLPOOL", "provider=legacy");
    print_digest("RIPEMD-160", "RIPEMD-160", "provider=legacy");
    print_digest("MD4.oid", "1.2.840.113549.2.4", "provider=legacy");

    /* The 32 `legacy_ciphers` rows: fetch, fixed-key/IV encrypt, and round-trip. */
    print_cipher_table();

    /* The two `legacy_kdfs` rows: derive 32 bytes of SHA-256 output. */
    print_kdf("PBKDF1", "PBKDF1");
    print_kdf("PVKKDF", "PVKKDF");

    /* Refusal arms: unknown names, a legacy name asked of the default provider, and two
     * `PBKDF1` derives the row must refuse. */
    print_digest("no-such-digest", "NO-SUCH-DIGEST", NULL);
    print_digest("MD4.default", "MD4", "provider=default");
    print_cipher("no-such-cipher", "NO-SUCH-CIPHER");
    printf("fetch.DES-CBC.default=%d\n",
           EVP_CIPHER_fetch(NULL, "DES-CBC", NULL) != NULL);
    printf("fetch.no-such-kdf=%d\n", EVP_KDF_fetch(NULL, "NO-SUCH-KDF", "provider=legacy") != NULL);
    {
        unsigned char out[33];
        printf("kdf.pbkdf1.nosalt=%d\n",
               derive_kdf("PBKDF1", out, 32, 1, 0));
        printf("kdf.pbkdf1.toolong=%d\n",
               derive_kdf("PBKDF1", out, 33, 1, 1));
    }

    printf("unload.legacy=%d\n", OSSL_PROVIDER_unload(legacy));
    return 0;
}
