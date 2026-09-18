/*
 * RT-HPKE -- the RFC 9180 `OSSL_HPKE_*` surface, `crypto/hpke/hpke.c`.
 *
 * What this court had to build, and why
 * --------------------------------------
 * HPKE is not an algorithm this crate implements: it is a KEM-encapsulation layer over `EVP_PKEY`'s
 * KEM operations, `EVP_KDF`'s HKDF and an `EVP_CIPHER` in AEAD mode. Every one of those three is a
 * *provider* method, so nothing in `crypto/hpke/hpke.c` is reachable from a probe without a
 * provider that publishes them -- and there is no default provider on the candidate side. The
 * provider below is therefore the only door, and it publishes:
 *
 *   * **`X25519` keymgmt** -- a 32-byte key with `pub`/`priv` import, `encoded-pub-key` get, and
 *     `query_operation_name(OSSL_OP_KEM)` answering `COURTKEM`. `hpke.c` builds its peer keys with
 *     `EVP_PKEY_new_raw_public_key_ex(libctx, kem_info->keytype, ...)` (`hpke.c:480`), so the
 *     keymgmt *must* be named `X25519`; the KEM is a separate name and is reached through the
 *     query.
 *   * **`COURTKEM`** -- deterministic encapsulation: `enc = f(pub)` and `secret = g(pub, enc)`, so
 *     a receiver whose private key holds the same bytes computes `g(priv, enc) == secret`. That is
 *     the whole property HPKE needs from the KEM, and it is what makes the `encap`/`decap` arms a
 *     round trip rather than two independent answers.
 *   * **`HKDF`** -- a real HKDF-SHA256 (the probe carries its own SHA-256), because
 *     `ossl_kdf_ctx_create` (`hpke_util.c:393`) fetches it by name and `kdf_derive`
 *     (`hpke_util.c:247`) drives it with `mode`/`salt`/`key`/`info`.
 *   * **`aes-128-gcm`** -- an AEAD whose `update` XORs a keystream and whose `final` computes or
 *     checks a tag over the ciphertext, reached through `EVP_CIPHER_CTX_ctrl`'s `ivlen`/`tag`
 *     parameters (`crypto/evp/evp_enc.c`), which is what `hpke_aead_enc`/`_dec` use.
 *
 * The mesh of `EVP_AEAD` the plan's row names does not exist
 * ----------------------------------------------------------
 * The brief for this subphase says the layer is "over `EVP_KEM`, `EVP_KDF` and, importantly,
 * `EVP_AEAD` (`crypto/evp/evp_aead.c`)". There is **no `EVP_AEAD` object in this authority**: no
 * `EVP_AEAD*` identifier appears anywhere in the pinned source, there is no `crypto/evp/evp_aead.c`
 * in the manifest, and `include/crypto/evp.h` declares neither. The AEAD is an `EVP_CIPHER` in
 * GCM mode, which is this stratum's own 7.3b/7.3c work -- and that is why no export is withheld on
 * a dependency the row names. The measurement is recorded in `docs/DECISIONS.md` D195.
 *
 * The arms
 * --------
 *   * the parameter getters and their validation: `OSSL_HPKE_suite_check`, `OSSL_HPKE_str2suite`
 *     (names and numbers, its two silent refusals and its one raising refusal),
 *     `OSSL_HPKE_get_ciphertext_size`/`get_public_encap_size`/`get_recommended_ikmelen`.
 *   * `OSSL_HPKE_CTX_new`'s three validations in order -- mode, suite, role -- and the
 *     export-only suite, which fetches no cipher at all.
 *   * `OSSL_HPKE_CTX_get_seq`/`set_seq`, including the sender's refusal.
 *   * `OSSL_HPKE_CTX_set1_psk`'s six validations, `set1_ikme`'s three, `set1_authpriv`'s three and
 *     `set1_authpub`'s receiver-only rule.
 *   * the **whole sequence**: `OSSL_HPKE_keygen` for the recipient, `encap` with `info`, `seal`,
 *     a receiver context, `decap`, `open`, and `OSSL_HPKE_export` on both sides -- and the
 *     two contexts' exported secrets are compared with each other, so the round trip is checked
 *     against the two sides agreeing rather than against the probe's own arithmetic.
 *   * the `OSSL_HPKE_CTX_free` boundary: a NULL free, and a fresh context after a free.
 *
 * Deliberately not observed
 * -------------------------
 *   * **`OSSL_HPKE_get_grease_value`**, which is `NOT_MEASURED` in the ledger: it needs
 *     `RAND_bytes_ex` and `ossl_rand_uniform_uint32` (`hpke.c:1433`, `hpke_util.c:198`), both
 *     `crypto/rand/`'s and Phase 9's. The line below names it.
 *   * **`hpke_expansion`'s NULL out-parameter refusal** (`hpke.c:402`, raising at `:403`), which
 *     both public callers make unreachable by always passing non-NULL.
 *   * **`ossl_hpke_labeled_extract`/`_expand`'s `WPACKET` failure arm** (`hpke_util.c:329`,
 *     `:380`): the authority's buffer is sized as the exact sum of its pieces, so the arm is
 *     unreachable. The transcription writes the concatenation directly and the module doc says so.
 *   * **`OSSL_HPKE_CTX_set1_psk`'s malloc-failure arms**, unreachable without fault injection.
 *
 * No address is printed; every arm prints a return code, a length or the bytes of a value the two
 * sides derive independently.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

/* The error chain, drained and formatted. Nothing here is an address. */
static char *chain(char *buf, size_t n)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags, first = 1;
    size_t at = 0;

    buf[0] = '\0';
    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        const char *rsn = ERR_reason_error_string(e);
        int k = snprintf(buf + at, n - at, "%s%s@%s/%d", first ? "" : ",",
                         rsn == NULL ? "<no-string>" : rsn, func == NULL ? "<no-func>" : func, line);

        if (k < 0 || (size_t)k >= n - at)
            break;
        at += (size_t)k;
        first = 0;
    }
    if (first)
        snprintf(buf, n, "<empty>");
    ERR_clear_error();
    return buf;
}

/* The value **and** the chain it left, in one line. */
static void sayc(const char *key, long long v)
{
    char buf[512];

    printf("%s=%lld chain=%s\n", key, v, chain(buf, sizeof buf));
}

/* -------------------------------------------------------------------------------------------- */
/* SHA-256 and HMAC, for the probe's own HKDF.                                                   */
/* -------------------------------------------------------------------------------------------- */

struct sha256_ctx {
    unsigned int h[8];
    unsigned long long len;
    unsigned char buf[64];
    size_t buflen;
};

static const unsigned int K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(struct sha256_ctx *c, const unsigned char *p)
{
    unsigned int w[64], a, b, cc, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[i * 4] << 24) | ((unsigned int)p[i * 4 + 1] << 16)
               | ((unsigned int)p[i * 4 + 2] << 8) | (unsigned int)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);

        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        unsigned int S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        unsigned int ch = (e & f) ^ ((~e) & g);
        unsigned int t1 = h + S1 + ch + K256[i] + w[i];
        unsigned int S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        unsigned int maj = (a & b) ^ (a & cc) ^ (b & cc);
        unsigned int t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(struct sha256_ctx *c)
{
    static const unsigned int iv[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };

    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
    c->buflen = 0;
}

static void sha256_update(struct sha256_ctx *c, const unsigned char *in, size_t inl)
{
    c->len += inl;
    while (inl > 0) {
        size_t take = 64 - c->buflen;

        if (take > inl)
            take = inl;
        memcpy(c->buf + c->buflen, in, take);
        c->buflen += take;
        in += take;
        inl -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *c, unsigned char out[32])
{
    unsigned long long bits = c->len * 8;
    unsigned char pad = 0x80, zero = 0x00, lenbe[8];
    int i;

    sha256_update(c, &pad, 1);
    while (c->buflen != 56)
        sha256_update(c, &zero, 1);
    for (i = 0; i < 8; i++)
        lenbe[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(c, lenbe, 8);
    for (i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)c->h[i];
    }
}

static void hmac256(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen, unsigned char out[32])
{
    unsigned char k[64], ipad[64], opad[64], inner[32];
    struct sha256_ctx c;
    size_t i;

    memset(k, 0, sizeof k);
    if (keylen > 64) {
        sha256_init(&c);
        sha256_update(&c, key, keylen);
        sha256_final(&c, k);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = (unsigned char)(k[i] ^ 0x36);
        opad[i] = (unsigned char)(k[i] ^ 0x5c);
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

/* -------------------------------------------------------------------------------------------- */
/* The probe's provider.                                                                         */
/* -------------------------------------------------------------------------------------------- */

static char ct_marker;
#define KB 32

/* ---- the keymgmt --------------------------------------------------------------------------- */

struct km_key {
    unsigned char pub[KB];
    unsigned char priv[KB];
    int has_priv;
    int index;
};

struct km_gen {
    unsigned char ikm[66];
    size_t ikmlen;
};

static void *km_new(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct km_key));
}

static void km_free(void *keydata)
{
    free(keydata);
}

static int km_has(const void *keydata, int selection)
{
    const struct km_key *k = keydata;

    if (k == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !k->has_priv)
        return 0;
    return 1;
}

static int km_get_params(void *keydata, OSSL_PARAM params[])
{
    struct km_key *k = keydata;
    OSSL_PARAM *p;

    if (k == NULL)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, k->pub, KB))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, k->pub, KB))
        return 0;
    return 1;
}

static const OSSL_PARAM *km_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;
    return table;
}

static int km_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    struct km_key *k = keydata;
    const OSSL_PARAM *p;
    const void *data = NULL;
    size_t len = 0;

    if (k == NULL)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (!OSSL_PARAM_get_octet_string_ptr(p, &data, &len) || data == NULL || len != KB)
            return 0;
        memcpy(k->pub, data, KB);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        if (!OSSL_PARAM_get_octet_string_ptr(p, &data, &len) || data == NULL || len != KB)
            return 0;
        memcpy(k->priv, data, KB);
        k->has_priv = 1;
        /* A raw private key carries no public half here, so the probe's `priv` and `pub` agree --
         * which is exactly the KEM's premise in `kem_encapsulate`/`kem_decapsulate`. */
        memcpy(k->pub, data, KB);
    }
    (void)selection;
    return 1;
}

static const OSSL_PARAM *km_import_types(int selection)
{
    static const OSSL_PARAM pub[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    static const OSSL_PARAM priv[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return priv;
    return pub;
}

static int km_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg)
{
    struct km_key *k = keydata;
    OSSL_PARAM params[2];
    unsigned char *pub = NULL;

    if (k == NULL || cb == NULL)
        return 0;
    pub = k->pub;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, KB);
    params[1] = OSSL_PARAM_construct_end();
    (void)selection;
    return cb(params, cbarg);
}

static const char *km_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_KEM)
        return "COURTKEM";
    return NULL;
}

static void *km_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void)provctx;
    (void)selection;
    (void)params;
    return calloc(1, sizeof(struct km_gen));
}

static void km_gen_cleanup(void *genctx)
{
    free(genctx);
}

static int km_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct km_gen *g = genctx;
    const OSSL_PARAM *p;
    const void *data = NULL;
    size_t len = 0;

    if (g == NULL)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DHKEM_IKM);
    if (p != NULL && OSSL_PARAM_get_octet_string_ptr(p, &data, &len) && data != NULL
        && len <= sizeof g->ikm) {
        memcpy(g->ikm, data, len);
        g->ikmlen = len;
    }
    return 1;
}

static const OSSL_PARAM *km_gen_settable_params(void *genctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, NULL, 0),
        OSSL_PARAM_END
    };

    (void)genctx;
    (void)provctx;
    return table;
}

static void *km_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    struct km_gen *g = genctx;
    struct km_key *k = calloc(1, sizeof *k);
    int i;

    (void)cb;
    (void)cbarg;
    if (k == NULL)
        return NULL;
    for (i = 0; i < KB; i++) {
        unsigned char seed = (unsigned char)(g != NULL && g->ikmlen > 0 ? g->ikm[i % g->ikmlen]
                                                                            : 0x11);
        k->pub[i] = (unsigned char)(seed ^ (unsigned char)(0x40 + i));
        k->priv[i] = k->pub[i];
    }
    k->has_priv = 1;
    return k;
}

static const OSSL_DISPATCH km_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))km_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))km_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))km_gettable_params },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))km_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))km_import_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))km_query_operation_name },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))km_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))km_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))km_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))km_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))km_gen },
    { 0, NULL }
};

/* ---- the KEM -------------------------------------------------------------------------------- */

struct kem_ctx {
    unsigned char key[KB];
};

static void *kem_newctx(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct kem_ctx));
}

static void kem_freectx(void *vctx)
{
    free(vctx);
}

static int kem_encapsulate_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{
    struct kem_ctx *c = vctx;
    struct km_key *k = provkey;

    (void)params;
    if (c == NULL || k == NULL)
        return 0;
    memcpy(c->key, k->pub, KB);
    return 1;
}

static int kem_decapsulate_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{
    struct kem_ctx *c = vctx;
    struct km_key *k = provkey;

    (void)params;
    if (c == NULL || k == NULL)
        return 0;
    memcpy(c->key, k->has_priv ? k->priv : k->pub, KB);
    return 1;
}

static int kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                           unsigned char *secret, size_t *secretlen)
{
    struct kem_ctx *c = vctx;
    int i;

    if (c == NULL)
        return 0;
    if (out == NULL) {
        *outlen = KB;
        *secretlen = KB;
        return 1;
    }
    if (*outlen < KB || secret == NULL || *secretlen < KB)
        return 0;
    for (i = 0; i < KB; i++)
        out[i] = (unsigned char)(c->key[i] ^ 0x5a);
    for (i = 0; i < KB; i++)
        secret[i] = (unsigned char)(c->key[i] ^ out[i] ^ (unsigned char)(i * 7 + 1));
    *outlen = KB;
    *secretlen = KB;
    return 1;
}

static int kem_decapsulate(void *vctx, unsigned char *secret, size_t *secretlen,
                           const unsigned char *in, size_t inlen)
{
    struct kem_ctx *c = vctx;
    int i;

    if (c == NULL || in == NULL || inlen != KB)
        return 0;
    if (secret == NULL) {
        *secretlen = KB;
        return 1;
    }
    if (*secretlen < KB)
        return 0;
    for (i = 0; i < KB; i++)
        secret[i] = (unsigned char)(c->key[i] ^ in[i] ^ (unsigned char)(i * 7 + 1));
    *secretlen = KB;
    return 1;
}

static const OSSL_DISPATCH kem_fns[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kem_decapsulate },
    { 0, NULL }
};

/* ---- the KDF -------------------------------------------------------------------------------- */

struct kdf_ctx {
    char digest[32];
    int have_digest;
};

static void *kdf_newctx(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct kdf_ctx));
}

static void kdf_freectx(void *vctx)
{
    free(vctx);
}

static int kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct kdf_ctx *c = vctx;
    const OSSL_PARAM *p;

    if (c == NULL)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p != NULL) {
        const char *s = NULL;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &s) || s == NULL)
            return 0;
        strncpy(c->digest, s, sizeof c->digest - 1);
        c->digest[sizeof c->digest - 1] = '\0';
        c->have_digest = 1;
    }
    /* `properties` is accepted and ignored: the probe's provider is the only one loaded. */
    return 1;
}

static const OSSL_PARAM *kdf_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return table;
}

static const OSSL_PARAM *kdf_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM table[] = { OSSL_PARAM_END };

    (void)vctx;
    (void)provctx;
    return table;
}

static int kdf_get_params(OSSL_PARAM params[])
{
    (void)params;
    return 1;
}

static int kdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
    struct kdf_ctx *c = vctx;
    const OSSL_PARAM *p;
    int mode = 0;
    const void *salt = NULL, *ikm = NULL, *info = NULL;
    size_t saltlen = 0, ikmlen = 0, infolen = 0;
    unsigned char zeros[32];
    unsigned char prk[32];
    unsigned char t[32];
    size_t done = 0;
    unsigned char counter = 1;
    unsigned char hbuf[1 + 1024 + 1];
    size_t hbuflen;

    if (c == NULL || key == NULL || keylen == 0 || !c->have_digest)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_get_int(p, &mode))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p != NULL && !OSSL_PARAM_get_octet_string_ptr(p, &salt, &saltlen))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p != NULL && !OSSL_PARAM_get_octet_string_ptr(p, &ikm, &ikmlen))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
    if (p != NULL && !OSSL_PARAM_get_octet_string_ptr(p, &info, &infolen))
        return 0;

    memset(zeros, 0, sizeof zeros);
    if (mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
        const unsigned char *use_salt = salt;

        if (use_salt == NULL || saltlen == 0) {
            use_salt = zeros;
            saltlen = 32;
        }
        if (keylen != 32)
            return 0;
        hmac256(use_salt, saltlen, ikm == NULL ? zeros : ikm, ikmlen, key);
        return 1;
    }
    if (mode != EVP_KDF_HKDF_MODE_EXPAND_ONLY || ikm == NULL || ikmlen != 32)
        return 0;
    memcpy(prk, ikm, 32);
    while (done < keylen) {
        if (infolen > 1024)
            return 0;
        hbuflen = 0;
        if (done > 0) {
            memcpy(hbuf, t, 32);
            hbuflen = 32;
        }
        if (infolen > 0) {
            memcpy(hbuf + hbuflen, info, infolen);
            hbuflen += infolen;
        }
        hbuf[hbuflen++] = counter;
        hmac256(prk, 32, hbuf, hbuflen, t);
        {
            size_t take = keylen - done;

            if (take > 32)
                take = 32;
            memcpy(key + done, t, take);
            done += take;
        }
        counter++;
    }
    return 1;
}

static const OSSL_DISPATCH kdf_fns[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))kdf_newctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))kdf_freectx },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))kdf_derive },
    { OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void))kdf_get_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))kdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))kdf_set_ctx_params },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))kdf_settable_ctx_params },
    { 0, NULL }
};

/* ---- the AEAD cipher ------------------------------------------------------------------------ */

struct aead_ctx {
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char tag[16];
    size_t taglen;
    unsigned int sum;
    int enc;
    int have_key;
};

static void *aead_newctx(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct aead_ctx));
}

static void aead_freectx(void *vctx)
{
    free(vctx);
}

static void *aead_dupctx(void *vctx)
{
    struct aead_ctx *src = vctx;
    struct aead_ctx *dst = calloc(1, sizeof *dst);

    if (dst == NULL || src == NULL) {
        free(dst);
        return NULL;
    }
    memcpy(dst, src, sizeof *dst);
    return dst;
}

static int aead_init(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[], int enc)
{
    struct aead_ctx *c = vctx;

    (void)params;
    if (c == NULL)
        return 0;
    c->enc = enc;
    c->sum = 0;
    c->taglen = 0;
    if (key != NULL) {
        if (keylen != 16)
            return 0;
        memcpy(c->key, key, 16);
        c->have_key = 1;
    }
    if (iv != NULL) {
        if (ivlen != 0 && ivlen != 12)
            return 0;
        memcpy(c->iv, iv, 12);
    }
    return 1;
}

static int aead_einit(void *vctx, const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return aead_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int aead_dinit(void *vctx, const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return aead_init(vctx, key, keylen, iv, ivlen, params, 0);
}

static int aead_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                       const unsigned char *in, size_t inl)
{
    struct aead_ctx *c = vctx;
    size_t i;

    if (c == NULL || !c->have_key || in == NULL)
        return 0;
    /* A NULL output is the AAD call `hpke_aead_enc`/`_dec` make
     * (`crypto/hpke/hpke.c:261`, `:178`): nothing is written and the AAD is not mixed into the
     * probe's tag, which both sides do identically. */
    if (out == NULL) {
        *outl = 0;
        return 1;
    }
    if (outsize < inl)
        return 0;
    for (i = 0; i < inl; i++) {
        unsigned char ks = (unsigned char)(c->key[i % 16] ^ c->iv[i % 12] ^ (unsigned char)(i + 1));

        out[i] = (unsigned char)(in[i] ^ ks);
        c->sum += c->enc ? out[i] : in[i];
    }
    *outl = inl;
    return 1;
}

static void aead_expected_tag(struct aead_ctx *c, unsigned char tag[16])
{
    int i;

    for (i = 0; i < 16; i++)
        tag[i] = (unsigned char)(c->key[i] ^ c->iv[i % 12] ^ (unsigned char)(i + 1)
                                 ^ (unsigned char)(c->sum & 0xff));
}

static int aead_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    struct aead_ctx *c = vctx;
    unsigned char want[16];

    (void)out;
    (void)outsize;
    if (c == NULL)
        return 0;
    aead_expected_tag(c, want);
    *outl = 0;
    if (c->enc) {
        memcpy(c->tag, want, 16);
        c->taglen = 16;
        return 1;
    }
    if (c->taglen != 16)
        return 0;
    return memcmp(c->tag, want, 16) == 0;
}

static int aead_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 12))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_GCM_MODE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_PARAM *aead_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return table;
}

static int aead_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct aead_ctx *c = vctx;
    OSSL_PARAM *p;

    if (c == NULL)
        return 0;
    p = OSSL_PARAM_locate(params, "tag");
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, c->tag, c->taglen == 0 ? 16 : c->taglen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 12))
        return 0;
    /* `evp_cipher_init_internal` reads the key length through `EVP_CIPHER_CTX_get_key_length` and
     * hands it to `einit`, so a provider that does not answer `keylen` gets 0 and a non-NULL key is
     * refused. */
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    return 1;
}

static int aead_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct aead_ctx *c = vctx;
    const OSSL_PARAM *p;

    if (c == NULL)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        size_t ivlen = 0;

        if (!OSSL_PARAM_get_size_t(p, &ivlen) || ivlen != 12)
            return 0;
    }
    p = OSSL_PARAM_locate_const(params, "tag");
    if (p != NULL) {
        const void *data = NULL;
        size_t len = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, &data, &len) || data == NULL || len != 16)
            return 0;
        memcpy(c->tag, data, 16);
        c->taglen = 16;
    }
    return 1;
}

static const OSSL_PARAM *aead_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_octet_string("tag", NULL, 0),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return table;
}

static const OSSL_PARAM *aead_settable_ctx_params(void *vctx, void *provctx)
{
    return aead_gettable_ctx_params(vctx, provctx);
}

static const OSSL_DISPATCH aead_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))aead_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))aead_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))aead_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aead_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))aead_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))aead_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))aead_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))aead_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))aead_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))aead_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))aead_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))aead_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))aead_settable_ctx_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM ct_keymgmts[] = {
    { "X25519:courtx25519", "provider=court-hpke", km_fns, "the probe's own keymgmt" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM ct_kems[] = {
    { "COURTKEM:courtkem", "provider=court-hpke", kem_fns, "the probe's own KEM" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM ct_kdfs[] = {
    { "HKDF:courthkdf", "provider=court-hpke", kdf_fns, "the probe's own HKDF" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM ct_ciphers[] = {
    { "aes-128-gcm", "provider=court-hpke", aead_fns, "the probe's own AEAD" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *ct_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return ct_keymgmts;
    if (operation_id == OSSL_OP_KEM)
        return ct_kems;
    if (operation_id == OSSL_OP_KDF)
        return ct_kdfs;
    if (operation_id == OSSL_OP_CIPHER)
        return ct_ciphers;
    return NULL;
}

static const OSSL_DISPATCH ct_provider_fns[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ct_query },
    { 0, NULL }
};

static int ct_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *out = ct_provider_fns;
    *provctx = &ct_marker;
    return 1;
}

/* -------------------------------------------------------------------------------------------- */
/* The arms.                                                                                     */
/* -------------------------------------------------------------------------------------------- */

#define SUITE_X25519_128 \
    { OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }

static void parameter_arms(void)
{
    OSSL_HPKE_SUITE s = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE bad = { OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256, 0x0099 };
    OSSL_HPKE_SUITE reserved = { OSSL_HPKE_KEM_ID_RESERVED, OSSL_HPKE_KDF_ID_HKDF_SHA256,
                                 OSSL_HPKE_AEAD_ID_AES_GCM_128 };

    sayn("suite.default", OSSL_HPKE_suite_check(s));
    sayc("suite.bad_aead", OSSL_HPKE_suite_check(bad));
    sayc("suite.reserved_kem", OSSL_HPKE_suite_check(reserved));

    printf("exp.default=%zu/%zu/%zu\n", OSSL_HPKE_get_public_encap_size(s),
           OSSL_HPKE_get_ciphertext_size(s, 0), OSSL_HPKE_get_recommended_ikmelen(s));
    printf("exp.p521=%zu/%zu/%zu\n",
           OSSL_HPKE_get_public_encap_size((OSSL_HPKE_SUITE){ OSSL_HPKE_KEM_ID_P521,
                                                              OSSL_HPKE_KDF_ID_HKDF_SHA512,
                                                              OSSL_HPKE_AEAD_ID_AES_GCM_256 }),
           OSSL_HPKE_get_ciphertext_size((OSSL_HPKE_SUITE){ OSSL_HPKE_KEM_ID_P521,
                                                            OSSL_HPKE_KDF_ID_HKDF_SHA512,
                                                            OSSL_HPKE_AEAD_ID_AES_GCM_256 }, 100),
           OSSL_HPKE_get_recommended_ikmelen((OSSL_HPKE_SUITE){ OSSL_HPKE_KEM_ID_P521,
                                                                OSSL_HPKE_KDF_ID_HKDF_SHA512,
                                                                OSSL_HPKE_AEAD_ID_AES_GCM_256 }));
    printf("exp.export_only=%zu/%zu/%zu\n",
           OSSL_HPKE_get_public_encap_size((OSSL_HPKE_SUITE){ OSSL_HPKE_KEM_ID_X25519,
                                                              OSSL_HPKE_KDF_ID_HKDF_SHA256,
                                                              OSSL_HPKE_AEAD_ID_EXPORTONLY }),
           OSSL_HPKE_get_ciphertext_size((OSSL_HPKE_SUITE){ OSSL_HPKE_KEM_ID_X25519,
                                                            OSSL_HPKE_KDF_ID_HKDF_SHA256,
                                                            OSSL_HPKE_AEAD_ID_EXPORTONLY }, 7),
           OSSL_HPKE_get_recommended_ikmelen((OSSL_HPKE_SUITE){ OSSL_HPKE_KEM_ID_X25519,
                                                                OSSL_HPKE_KDF_ID_HKDF_SHA256,
                                                                OSSL_HPKE_AEAD_ID_EXPORTONLY }));
    sayc("exp.bad", (long long)OSSL_HPKE_get_public_encap_size(bad));

    {
        OSSL_HPKE_SUITE out = { 0, 0, 0 };
        int rv;

        rv = OSSL_HPKE_str2suite("X25519,0x1,aes-128-gcm", &out);
        printf("str2suite.names=%d %04x/%04x/%04x\n", rv, out.kem_id, out.kdf_id, out.aead_id);
        rv = OSSL_HPKE_str2suite("P-256,hkdf-sha384,2", &out);
        printf("str2suite.numbers=%d %04x/%04x/%04x\n", rv, out.kem_id, out.kdf_id, out.aead_id);
        rv = OSSL_HPKE_str2suite("P-521,3,exporter", &out);
        printf("str2suite.exporter=%d %04x/%04x/%04x\n", rv, out.kem_id, out.kdf_id, out.aead_id);
        sayn("str2suite.trailing", OSSL_HPKE_str2suite("X25519,1,1,", &out));
        sayn("str2suite.one_delim", OSSL_HPKE_str2suite("X25519,1", &out));
        sayn("str2suite.unknown", OSSL_HPKE_str2suite("X25519,1,nope", &out));
        sayc("str2suite.empty", OSSL_HPKE_str2suite("", &out));
        sayc("str2suite.null", OSSL_HPKE_str2suite(NULL, &out));
    }
}

static void context_arms(OSSL_LIB_CTX *libctx)
{
    OSSL_HPKE_SUITE s = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE export_only = { OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
                                    OSSL_HPKE_AEAD_ID_EXPORTONLY };
    OSSL_HPKE_CTX *c;
    char errbuf[512];
    uint64_t seq = 0;
    unsigned char psk[32];
    unsigned char ikme[16];
    unsigned char rawkey[32];
    EVP_PKEY *akey = NULL;

    memset(psk, 0x33, sizeof psk);
    memset(ikme, 0x44, sizeof ikme);
    memset(rawkey, 0x55, sizeof rawkey);

    /* Mode and role refusals precede the cipher fetch, so they need no provider. */
    sayc("ctx.bad_mode",
         (int)(OSSL_HPKE_CTX_new(9, export_only, OSSL_HPKE_ROLE_SENDER, libctx, NULL) == NULL));
    sayc("ctx.bad_role",
         (int)(OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, export_only, 7, libctx, NULL) == NULL));
    sayc("ctx.bad_suite",
         (int)(OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, (OSSL_HPKE_SUITE){ 0, 0, 0 },
                                 OSSL_HPKE_ROLE_SENDER, libctx, NULL)
               == NULL));

    /* The real suite, in the private library context the probe's provider is loaded into. */
    c = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSK, s, OSSL_HPKE_ROLE_SENDER, libctx, NULL);
    printf("ctx.psk_mode=%d err=%s\n", (int)(c != NULL), chain(errbuf, sizeof errbuf));
    if (c != NULL) {
        printf("seq.get=%d v=%llu\n", OSSL_HPKE_CTX_get_seq(c, &seq), (unsigned long long)seq);
        /* A sender may not set its sequence. */
        sayc("seq.set_sender", OSSL_HPKE_CTX_set_seq(c, 3));
        /* The sender-only IKM. */
        sayc("ikme.ok", OSSL_HPKE_CTX_set1_ikme(c, ikme, sizeof ikme));
        sayc("ikme.empty", OSSL_HPKE_CTX_set1_ikme(c, ikme, 0));
        sayc("ikme.too_long", OSSL_HPKE_CTX_set1_ikme(c, ikme, 67));
        sayc("ikme.null", OSSL_HPKE_CTX_set1_ikme(c, NULL, 4));
        /* The PSK validations, in the authority's order. */
        sayc("psk.null_id", OSSL_HPKE_CTX_set1_psk(c, NULL, psk, 32));
        sayc("psk.too_short", OSSL_HPKE_CTX_set1_psk(c, "id", psk, 31));
        sayc("psk.ok", OSSL_HPKE_CTX_set1_psk(c, "id", psk, 32));
        sayc("psk.empty_id", OSSL_HPKE_CTX_set1_psk(c, "", psk, 32));
        sayc("psk.null_data", OSSL_HPKE_CTX_set1_psk(c, "id", NULL, 32));
        /* `set1_authpriv` on a sender with an AUTH-mode key is the acceptance case. */
        OSSL_HPKE_CTX_free(c);
    }
    c = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_AUTH, s, OSSL_HPKE_ROLE_RECEIVER, libctx, NULL);
    printf("ctx.auth_receiver=%d err=%s\n", (int)(c != NULL), chain(errbuf, sizeof errbuf));
    if (c != NULL) {
        sayc("seq.set_receiver", OSSL_HPKE_CTX_set_seq(c, 5));
        printf("seq.round_trip.get=%d v=%llu\n", OSSL_HPKE_CTX_get_seq(c, &seq),
               (unsigned long long)seq);
        /* A PSK on a non-PSK mode, and the sender-only IKM on a receiver, are refusals. */
        sayc("psk.wrong_mode", OSSL_HPKE_CTX_set1_psk(c, "id", psk, 32));
        sayc("ikme.receiver", OSSL_HPKE_CTX_set1_ikme(c, ikme, sizeof ikme));
        /* `set1_authpriv` with a real key on a receiver is the role refusal. */
        akey = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, rawkey, sizeof rawkey);
        printf("authpriv.key=%d err=%s\n", (int)(akey != NULL), chain(errbuf, sizeof errbuf));
        sayc("authpriv.receiver", OSSL_HPKE_CTX_set1_authpriv(c, akey));
        /* An encoded public value that is not 32 bytes is refused before it is stored. */
        sayc("authpub.garbage", OSSL_HPKE_CTX_set1_authpub(c, ikme, sizeof ikme));
        /* The receiver's acceptance case: a real 32-byte value. */
        sayc("authpub.ok", OSSL_HPKE_CTX_set1_authpub(c, rawkey, sizeof rawkey));
        sayc("authpub.null", OSSL_HPKE_CTX_set1_authpub(c, NULL, 32));
        EVP_PKEY_free(akey);
        OSSL_HPKE_CTX_free(c);
    }
    c = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, s, OSSL_HPKE_ROLE_SENDER, libctx, NULL);
    printf("ctx.base_sender=%d err=%s\n", (int)(c != NULL), chain(errbuf, sizeof errbuf));
    if (c != NULL) {
        /* Base mode: neither a PSK nor an IKM leaves the context uninitialised, so `encap` with a
         * short buffer is the size refusal. */
        unsigned char enc[64];
        size_t enclen = 8;

        sayc("encap.short_buffer",
             OSSL_HPKE_encap(c, enc, &enclen, rawkey, sizeof rawkey, NULL, 0));
        /* An `infolen` past the maximum is a refusal before the KEM is touched. */
        {
            static const unsigned char info[8] = { 0 };
            size_t len2 = sizeof enc;

            sayc("encap.info_too_long",
                 OSSL_HPKE_encap(c, enc, &len2, rawkey, sizeof rawkey, info, 1025));
        }
        /* `seal` before an `encap` has no key, which is the `key == NULL` refusal. */
        {
            unsigned char ctbuf[64];
            size_t ctlen = sizeof ctbuf;

            sayc("seal.no_key",
                 OSSL_HPKE_seal(c, ctbuf, &ctlen, NULL, 0, (const unsigned char *)"x", 1));
        }
        OSSL_HPKE_CTX_free(c);
    }

    /* The free boundary: NULL is accepted, and a fresh context is buildable afterwards. */
    OSSL_HPKE_CTX_free(NULL);
    c = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, export_only, OSSL_HPKE_ROLE_SENDER, libctx, NULL);
    printf("ctx.after_free=%d\n", c != NULL);
    OSSL_HPKE_CTX_free(c);
}

static void full_sequence(OSSL_LIB_CTX *libctx)
{
    OSSL_HPKE_SUITE s = OSSL_HPKE_SUITE_DEFAULT;
    static const unsigned char info[5] = { 1, 2, 3, 4, 5 };
    static const unsigned char aad[3] = { 9, 8, 7 };
    static const unsigned char pt[11] = "hello hpke";
    unsigned char su_pub[64], ru_pub[64];
    size_t su_publen = sizeof su_pub, ru_publen = sizeof ru_pub;
    EVP_PKEY *ru_priv = NULL;
    OSSL_HPKE_CTX *su = NULL, *ru = NULL;
    unsigned char enc[64], ct[64], rt[64];
    size_t enclen = sizeof enc, ctlen = sizeof ct, rtlen = sizeof rt;
    unsigned char su_exp[32], ru_exp[32];
    char errbuf[512];
    int rv;
    uint64_t lastseq = 0;

    /* The recipient's key pair, produced by the surface itself. */
    rv = OSSL_HPKE_keygen(s, ru_pub, &ru_publen, &ru_priv, NULL, 0, libctx, NULL);
    printf("seq.keygen=%d publen=%zu err=%s\n", rv, ru_publen, chain(errbuf, sizeof errbuf));
    if (rv != 1 || ru_priv == NULL)
        return;
    /* The keygen filled the buffer with the encoded public value, and the same value is what the
     * sender will import; the probe reads it back through the surface to make that relation a
     * measurement rather than an assumption. */
    su_publen = sizeof su_pub;
    sayc("seq.keygen.pub_readback",
         EVP_PKEY_get_octet_string_param(ru_priv, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, su_pub,
                                         su_publen, &su_publen)
             == 1);
    printf("seq.keygen.pub_matches=%d publen=%zu\n",
           (int)(ru_publen == su_publen && memcmp(ru_pub, su_pub, su_publen) == 0), su_publen);

    /* The sender encapsulates against the recipient's public value. */
    su = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, s, OSSL_HPKE_ROLE_SENDER, libctx, NULL);
    printf("seq.sender_ctx=%d err=%s\n", (int)(su != NULL), chain(errbuf, sizeof errbuf));
    if (su == NULL) {
        EVP_PKEY_free(ru_priv);
        return;
    }
    rv = OSSL_HPKE_encap(su, enc, &enclen, ru_pub, ru_publen, info, sizeof info);
    printf("seq.encap=%d enclen=%zu err=%s\n", rv, enclen, chain(errbuf, sizeof errbuf));
    if (rv == 1) {
        rv = OSSL_HPKE_seal(su, ct, &ctlen, aad, sizeof aad, pt, sizeof pt);
        printf("seq.seal=%d ctlen=%zu err=%s\n", rv, ctlen, chain(errbuf, sizeof errbuf));
        sayc("seq.export_sender",
             OSSL_HPKE_export(su, su_exp, 32, (const unsigned char *)"label", 5));
        /* A second encap on the same context is refused. */
        {
            size_t again = sizeof enc;

            sayc("seq.encap_twice",
                 OSSL_HPKE_encap(su, enc, &again, ru_pub, ru_publen, info, sizeof info));
        }
    }

    /* The receiver decapsulates, then opens. */
    ru = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, s, OSSL_HPKE_ROLE_RECEIVER, libctx, NULL);
    printf("seq.receiver_ctx=%d err=%s\n", (int)(ru != NULL), chain(errbuf, sizeof errbuf));
    if (ru != NULL && rv == 1) {
        rv = OSSL_HPKE_decap(ru, enc, enclen, ru_priv, info, sizeof info);
        printf("seq.decap=%d err=%s\n", rv, chain(errbuf, sizeof errbuf));
        if (rv == 1) {
            rv = OSSL_HPKE_open(ru, rt, &rtlen, aad, sizeof aad, ct, ctlen);
            printf("seq.open=%d rtlen=%zu pt=%d err=%s\n", rv, rtlen,
                   (int)(rtlen == sizeof pt && memcmp(rt, pt, sizeof pt) == 0),
                   chain(errbuf, sizeof errbuf));
            sayc("seq.export_receiver",
                 OSSL_HPKE_export(ru, ru_exp, 32, (const unsigned char *)"label", 5));
            printf("seq.exports_agree=%d\n", memcmp(su_exp, ru_exp, 32) == 0);
            printf("seq.seq_after=%d v=%llu\n", OSSL_HPKE_CTX_get_seq(ru, &lastseq),
                   (unsigned long long)lastseq);
        }
        /* A corrupted tag is refused by the AEAD's final, which `open` reports as a failure. */
        if (rv == 1) {
            unsigned char badpt[64];
            size_t badlen = sizeof badpt;
            unsigned char badct[64];

            memcpy(badct, ct, ctlen);
            badct[ctlen - 1] ^= 0xff;
            sayc("seq.open_bad_tag",
                 OSSL_HPKE_open(ru, badpt, &badlen, aad, sizeof aad, badct, ctlen));
        }
    }

    /* A NULL private key is a refusal before any work. */
    if (ru != NULL) {
        sayc("seq.decap_null_priv", OSSL_HPKE_decap(ru, enc, enclen, NULL, info, sizeof info));
    }

    OSSL_HPKE_CTX_free(ru);
    OSSL_HPKE_CTX_free(su);
    EVP_PKEY_free(ru_priv);
}

int main(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (OSSL_PROVIDER_add_builtin(libctx, "court-hpke", ct_provider_init))
        prov = OSSL_PROVIDER_load(libctx, "court-hpke");
    sayn("provider.loaded", prov != NULL);

    parameter_arms();
    context_arms(libctx);
    /* The full sequence runs in the private library context the probe's provider is loaded into,
     * which every call that takes one is handed, so the probe's provider is the only one the
     * fetches can reach. */
    full_sequence(libctx);

    printf("OSSL_HPKE_get_grease_value=NOT_MEASURED_RAND_bytes_ex_IS_PHASE_9_hpke_c_1433\n");
    printf("hpke_expansion=NOT_MEASURED_NULL_OUT_PARAM_hpke_c_403\n");
    printf("ossl_hpke_labeled_extract=NOT_MEASURED_WPACKET_FAILURE_hpke_util_c_329\n");

    if (prov != NULL)
        OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}
