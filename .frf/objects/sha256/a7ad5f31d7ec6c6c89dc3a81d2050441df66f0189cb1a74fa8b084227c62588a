/*
 * RT-EVP-DISPATCH — the Phase 19.2 EVP / cipher dispatch comparison.
 *
 * What it measures
 * ----------------
 * 19.1 measured the CPU-capability surface: what the candidate *reports* under a fixed and faulted
 * CPUID facade. 19.2 measures the decision that surface feeds: for a fixed set of operations, which
 * implementation a legacy constructor, a provider fetch or a cipher/digest context *selects*, and
 * how that selection moves when the `OPENSSL_ia32cap` facade masks the capability set.
 *
 * The same source compiles twice, once against the admitted authority and once against the
 * candidate distribution shell, and every `key=value` line is a function of the library under test
 * and the process environment alone: no address, no clock and no duration is printed, so
 * `forensics/tools/probe_hygiene.py` sees the same transcript at `-O0`, `-O1` and `-O2`.
 *
 * The surface
 * -----------
 * For each operation the probe reports the identity the public API answers -- `name`, `NID`/`type`,
 * `flags`, block/key/IV sizes, whether the method carries a provider (`prov_null`) and, for a
 * provider fetch, the provider's own name and whether the canonical alias resolves:
 *
 *   * the **legacy constructor** path (`EVP_aes_128_cbc()`, `EVP_sha256()`, ...), which is the
 *     compiled-in `EVP_CIPHER`/`EVP_MD` static;
 *   * the **provider fetch** path (`EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL)` /
 *     `EVP_MD_fetch(NULL, "SHA256", NULL)`), which is the default provider's dispatch;
 *   * the **legacy name lookup** path (`EVP_get_cipherbyname` / `EVP_get_digestbyname`), the
 *     `EVP_CIPHER_do_all`-style added-cipher store;
 *   * the **cipher context** path (`EVP_CipherInit_ex2` over a fetched cipher, then
 *     `EVP_CIPHER_CTX_get0_cipher`), which is what a context selects for an operation.
 *
 * The fixed and faulted CPUID facade
 * ----------------------------------
 * The court runs this probe under a fixed `OPENSSL_ia32cap` value (`crypto/cpuid.c`
 * `OPENSSL_cpuid_setup` masks the capability vector). On the authority that mask reaches the
 * default provider's capability filter: `ossl_cipher_capable_aes_cbc_hmac_sha1` is
 * `AESNI_CBC_HMAC_SHA_CAPABLE` (`OPENSSL_ia32cap_P[1] & (1 << 25)`), so clearing the AES-NI bit
 * removes the `AES-*-CBC-HMAC-*` rows from the provider's exported table and their fetch answers
 * NULL, while the legacy `EVP_aes_*_cbc_hmac_sha*()` constructor answers NULL too. That movement is
 * the section-3.2 authority-linked differential control: a court whose facade cannot move the
 * authority's dispatch has not driven the surface.
 *
 * The candidate reads the same AES-NI bit from `CPUID.(EAX=1).ECX` directly
 * (`src/provider/cipher.rs:10560 ia32cap_aesni`) and does not model the `OPENSSL_ia32cap` mask, so
 * its selection does not move with the facade. That disposition -- and every other
 * candidate-vs-authority difference -- is *recorded* in the court's `divergences` block, not failed.
 *
 * Not a claim
 * -----------
 * This is a bounded comparison of *selection* over the capability sets the court drives, not a
 * benchmark and not an assembly-versus-Rust equivalence claim (docs/PHASE-19-SUBPHASES.md section
 * 3.6). A path the probe cannot reach is recorded, not assumed. The engine path is not driven: no
 * engine is configured and the reduced engine does not export the enumeration this would need.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>

typedef enum { OP_CIPHER, OP_DIGEST } op_kind;

typedef struct {
    const char *id;    /* the key fragment, e.g. "aes-128-cbc" */
    const char *name;  /* the canonical fetch/lookup name, e.g. "AES-128-CBC" */
    op_kind kind;
    const EVP_CIPHER *(*cipher)(void);
    const EVP_MD *(*md)(void);
} op_t;

static const EVP_CIPHER *c_aes_128_cbc(void) { return EVP_aes_128_cbc(); }
static const EVP_CIPHER *c_aes_256_cbc(void) { return EVP_aes_256_cbc(); }
static const EVP_CIPHER *c_aes_128_gcm(void) { return EVP_aes_128_gcm(); }
static const EVP_CIPHER *c_aes_256_gcm(void) { return EVP_aes_256_gcm(); }
static const EVP_CIPHER *c_chacha20_poly1305(void) { return EVP_chacha20_poly1305(); }
static const EVP_CIPHER *c_aes_128_cbc_hmac_sha1(void) { return EVP_aes_128_cbc_hmac_sha1(); }
static const EVP_CIPHER *c_aes_256_cbc_hmac_sha1(void) { return EVP_aes_256_cbc_hmac_sha1(); }
static const EVP_CIPHER *c_aes_128_cbc_hmac_sha256(void) { return EVP_aes_128_cbc_hmac_sha256(); }
static const EVP_CIPHER *c_aes_256_cbc_hmac_sha256(void) { return EVP_aes_256_cbc_hmac_sha256(); }
static const EVP_MD *m_sha1(void) { return EVP_sha1(); }
static const EVP_MD *m_sha256(void) { return EVP_sha256(); }

/* The fixed operation set. The court's schema in `forensics/tools/phase19_courts.py` is built from
 * the same ids, so an op added here without the schema is caught as a missing key. */
static const op_t OPS[] = {
    { "aes-128-cbc", "AES-128-CBC", OP_CIPHER, c_aes_128_cbc, NULL },
    { "aes-256-cbc", "AES-256-CBC", OP_CIPHER, c_aes_256_cbc, NULL },
    { "aes-128-gcm", "AES-128-GCM", OP_CIPHER, c_aes_128_gcm, NULL },
    { "aes-256-gcm", "AES-256-GCM", OP_CIPHER, c_aes_256_gcm, NULL },
    { "chacha20-poly1305", "CHACHA20-POLY1305", OP_CIPHER, c_chacha20_poly1305, NULL },
    { "aes-128-cbc-hmac-sha1", "AES-128-CBC-HMAC-SHA1", OP_CIPHER, c_aes_128_cbc_hmac_sha1, NULL },
    { "aes-256-cbc-hmac-sha1", "AES-256-CBC-HMAC-SHA1", OP_CIPHER, c_aes_256_cbc_hmac_sha1, NULL },
    { "aes-128-cbc-hmac-sha256", "AES-128-CBC-HMAC-SHA256", OP_CIPHER, c_aes_128_cbc_hmac_sha256, NULL },
    { "aes-256-cbc-hmac-sha256", "AES-256-CBC-HMAC-SHA256", OP_CIPHER, c_aes_256_cbc_hmac_sha256, NULL },
    { "sha1", "SHA1", OP_DIGEST, NULL, m_sha1 },
    { "sha256", "SHA256", OP_DIGEST, NULL, m_sha256 },
};
#define NOPS ((int)(sizeof(OPS) / sizeof(OPS[0])))

static void mk(char *out, size_t cap, const char *pfx, const char *id, const char *field)
{
    snprintf(out, cap, "%s.%s.%s", pfx, id, field);
}

static void kv(const char *key, const char *value)
{
    printf("%s=%s\n", key, value != NULL ? value : "");
}

static void kl(const char *key, long long value)
{
    printf("%s=%lld\n", key, value);
}

static void kul(const char *key, unsigned long value)
{
    printf("%s=%lu\n", key, value);
}

/* The identity every cipher path answers. `prov_null` is 1 when the method carries no provider
 * (the legacy static), 0 when it does. All fields are always emitted, `n/a` when the pointer is
 * NULL, so both sides' transcripts carry the same key count. */
static void emit_cipher(const char *pfx, const char *id, const EVP_CIPHER *c)
{
    char k[160];
    const OSSL_PROVIDER *prov = c != NULL ? EVP_CIPHER_get0_provider(c) : NULL;

    mk(k, sizeof k, pfx, id, "null"); kl(k, c == NULL);
    mk(k, sizeof k, pfx, id, "name"); kv(k, c != NULL ? EVP_CIPHER_get0_name(c) : NULL);
    mk(k, sizeof k, pfx, id, "nid"); kl(k, c != NULL ? EVP_CIPHER_get_nid(c) : -1);
    mk(k, sizeof k, pfx, id, "flags"); kul(k, c != NULL ? EVP_CIPHER_get_flags(c) : 0);
    mk(k, sizeof k, pfx, id, "type"); kl(k, c != NULL ? EVP_CIPHER_get_type(c) : -1);
    mk(k, sizeof k, pfx, id, "block"); kl(k, c != NULL ? EVP_CIPHER_get_block_size(c) : -1);
    mk(k, sizeof k, pfx, id, "keylen"); kl(k, c != NULL ? EVP_CIPHER_get_key_length(c) : -1);
    mk(k, sizeof k, pfx, id, "ivlen"); kl(k, c != NULL ? EVP_CIPHER_get_iv_length(c) : -1);
    mk(k, sizeof k, pfx, id, "prov_null"); kl(k, c != NULL ? (prov == NULL) : -1);
}

static void emit_md(const char *pfx, const char *id, const EVP_MD *m)
{
    char k[160];
    const OSSL_PROVIDER *prov = m != NULL ? EVP_MD_get0_provider(m) : NULL;

    mk(k, sizeof k, pfx, id, "null"); kl(k, m == NULL);
    mk(k, sizeof k, pfx, id, "name"); kv(k, m != NULL ? EVP_MD_get0_name(m) : NULL);
    mk(k, sizeof k, pfx, id, "nid"); kl(k, m != NULL ? EVP_MD_get_type(m) : -1);
    mk(k, sizeof k, pfx, id, "flags"); kul(k, m != NULL ? EVP_MD_get_flags(m) : 0);
    mk(k, sizeof k, pfx, id, "size"); kl(k, m != NULL ? EVP_MD_get_size(m) : -1);
    mk(k, sizeof k, pfx, id, "block"); kl(k, m != NULL ? EVP_MD_get_block_size(m) : -1);
    mk(k, sizeof k, pfx, id, "prov_null"); kl(k, m != NULL ? (prov == NULL) : -1);
}

/* The provider fetch path additionally names the provider and resolves the canonical alias. */
static void emit_cipher_prov(const char *id, const char *canonical, const EVP_CIPHER *c)
{
    char k[160];
    const OSSL_PROVIDER *prov = c != NULL ? EVP_CIPHER_get0_provider(c) : NULL;

    emit_cipher("fetch", id, c);
    mk(k, sizeof k, "fetch", id, "prov_name");
    kv(k, prov != NULL ? OSSL_PROVIDER_get0_name(prov) : NULL);
    mk(k, sizeof k, "fetch", id, "is_a"); kl(k, c != NULL ? EVP_CIPHER_is_a(c, canonical) : -1);
}

static void emit_md_prov(const char *id, const char *canonical, const EVP_MD *m)
{
    char k[160];
    const OSSL_PROVIDER *prov = m != NULL ? EVP_MD_get0_provider(m) : NULL;

    emit_md("fetch", id, m);
    mk(k, sizeof k, "fetch", id, "prov_name");
    kv(k, prov != NULL ? OSSL_PROVIDER_get0_name(prov) : NULL);
    mk(k, sizeof k, "fetch", id, "is_a"); kl(k, m != NULL ? EVP_MD_is_a(m, canonical) : -1);
}

/* The cipher context path: what `EVP_CipherInit_ex2` selects for an operation. */
static void emit_cipher_ctx(const char *id, const EVP_CIPHER *c)
{
    char k[160];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *sel = NULL;
    int init = 0;

    if (ctx != NULL && c != NULL) {
        init = EVP_CipherInit_ex2(ctx, c, NULL, NULL, 1, NULL);
        if (init == 1)
            sel = EVP_CIPHER_CTX_get0_cipher(ctx);
    }
    {
        const OSSL_PROVIDER *prov = sel != NULL ? EVP_CIPHER_get0_provider(sel) : NULL;
        mk(k, sizeof k, "ctx", id, "init"); kl(k, (ctx != NULL && c != NULL) ? init : -1);
        mk(k, sizeof k, "ctx", id, "name");
        kv(k, sel != NULL ? EVP_CIPHER_get0_name(sel) : NULL);
        mk(k, sizeof k, "ctx", id, "nid");
        kl(k, sel != NULL ? EVP_CIPHER_get_nid(sel) : -1);
        mk(k, sizeof k, "ctx", id, "prov_name");
        kv(k, prov != NULL ? OSSL_PROVIDER_get0_name(prov) : NULL);
    }
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
}

int main(void)
{
    printf("probe.kind=evp-dispatch\n");

    /* The default provider and its own name: the context every provider-side selection happens in.
     * It is loaded once and kept alive until every fetch below has run; unloading it first would
     * tear the algorithm store down and make every fetch answer NULL on both sides. */
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    printf("prov.default.loaded=%d\n", defprov != NULL);
    printf("prov.default.name=%s\n",
           defprov != NULL ? OSSL_PROVIDER_get0_name(defprov) : "");

    /* Path 1: the legacy constructor, and path 3: the legacy name lookup. */
    for (int i = 0; i < NOPS; i++) {
        const op_t *op = &OPS[i];
        char k[160];
        if (op->kind == OP_CIPHER) {
            const EVP_CIPHER *c = op->cipher();
            emit_cipher("legacy", op->id, c);
            {
                const EVP_CIPHER *by_name = EVP_get_cipherbyname(op->name);
                mk(k, sizeof k, "lookup", op->id, "null"); kl(k, by_name == NULL);
                mk(k, sizeof k, "lookup", op->id, "nid");
                kl(k, by_name != NULL ? EVP_CIPHER_get_nid(by_name) : -1);
            }
        } else {
            const EVP_MD *m = op->md();
            emit_md("legacy", op->id, m);
            {
                const EVP_MD *by_name = EVP_get_digestbyname(op->name);
                mk(k, sizeof k, "lookup", op->id, "null"); kl(k, by_name == NULL);
                mk(k, sizeof k, "lookup", op->id, "nid");
                kl(k, by_name != NULL ? EVP_MD_get_type(by_name) : -1);
            }
        }
    }

    /* Path 2: the provider fetch. */
    for (int i = 0; i < NOPS; i++) {
        const op_t *op = &OPS[i];
        if (op->kind == OP_CIPHER) {
            EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, op->name, NULL);
            emit_cipher_prov(op->id, op->name, c);
            EVP_CIPHER_free(c);
        } else {
            EVP_MD *m = EVP_MD_fetch(NULL, op->name, NULL);
            emit_md_prov(op->id, op->name, m);
            EVP_MD_free(m);
        }
    }

    /* Path 4: the cipher-context selection, over the legacy constructor and over a fetch. */
    {
        char k[160];
        const EVP_CIPHER *c = EVP_aes_128_cbc();
        EVP_CIPHER *f = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
        EVP_CIPHER *g = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
        EVP_CIPHER *x = EVP_CIPHER_fetch(NULL, "CHACHA20-POLY1305", NULL);

        emit_cipher_ctx("aes-128-cbc", c);
        emit_cipher_ctx("aes-128-cbc-fetch", f);
        emit_cipher_ctx("aes-128-gcm-fetch", g);
        emit_cipher_ctx("chacha20-poly1305-fetch", x);

        /* A digest context selects its own method; reported for completeness. */
        {
            EVP_MD_CTX *mctx = EVP_MD_CTX_new();
            const EVP_MD *sel = NULL;
            int init = 0;
            EVP_MD *sha = EVP_MD_fetch(NULL, "SHA256", NULL);
            if (mctx != NULL && sha != NULL) {
                init = EVP_DigestInit_ex2(mctx, sha, NULL);
                if (init == 1)
                    sel = EVP_MD_CTX_get0_md(mctx);
            }
            mk(k, sizeof k, "ctx", "sha256-fetch", "init");
            kl(k, (mctx != NULL && sha != NULL) ? init : -1);
            mk(k, sizeof k, "ctx", "sha256-fetch", "name");
            kv(k, sel != NULL ? EVP_MD_get0_name(sel) : NULL);
            mk(k, sizeof k, "ctx", "sha256-fetch", "nid");
            kl(k, sel != NULL ? EVP_MD_get_type(sel) : -1);
            mk(k, sizeof k, "ctx", "sha256-fetch", "prov_name");
            {
                const OSSL_PROVIDER *prov = sel != NULL ? EVP_MD_get0_provider(sel) : NULL;
                kv(k, prov != NULL ? OSSL_PROVIDER_get0_name(prov) : NULL);
            }
            if (mctx != NULL)
                EVP_MD_CTX_free(mctx);
            EVP_MD_free(sha);
        }

        EVP_CIPHER_free(f);
        EVP_CIPHER_free(g);
        EVP_CIPHER_free(x);
    }

    printf("prov.default.unload=%d\n", defprov != NULL ? OSSL_PROVIDER_unload(defprov) : -1);
    printf("probe.done=1\n");
    return 0;
}
