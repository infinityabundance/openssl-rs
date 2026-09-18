/*
 * RT-EVP-PBE -- the PBE registry, the PBKDF2 facade and the three v2 keygens.
 *
 * 7.4c lands `crypto/evp/evp_pbe.c` whole, `crypto/evp/p5_crpt.c` whole, `crypto/evp/p5_crpt2.c`
 * whole and `crypto/asn1/p5_scrypt.c`'s two keygen exports. This probe observes all four, and it
 * needs a provider of its own to do it: `PKCS5_PBKDF2_HMAC` and every keygen below resolve their
 * algorithms through `EVP_KDF_fetch`/`EVP_CIPHER_fetch`/`EVP_MD_fetch`, and the candidate has no
 * provider that publishes any of them. So the probe declares one and *installs it as the default
 * library context's only provider*, which is what makes one source observe the same callbacks on
 * both sides:
 *
 *     OSSL_PROVIDER_add_builtin(myctx, "court-pbe", court_provider_init);
 *     OSSL_PROVIDER_load(myctx, "court-pbe");
 *     OSSL_LIB_CTX_set0_default(myctx);      // the thread default, which a NULL libctx resolves to
 *
 * `court-pbe` publishes three KDFs (`PBKDF1`, `PBKDF2`, `SCRYPT`), two digests (`SHA1`, `MD2`) and
 * two ciphers (`DES-CBC` with an 8-byte key, `DES-EDE3-CBC` with a 24-byte key). Every name is the
 * one the authority's own lookup asks for, which is why none of them is a choice:
 *
 *   * `OBJ_nid2sn(NID_des_cbc)` is `DES-CBC`, the cipher `EVP_PBE_CipherInit_ex` fetches for a row
 *     whose `cipher_nid` is `NID_des_cbc`;
 *   * `OBJ_nid2sn(NID_md2)` is `MD2`, the digest of the same row;
 *   * `OBJ_nid2sn(NID_sha1)` is `SHA1`, which is both `PKCS5_PBKDF2_HMAC_SHA1`'s fetch spelling
 *     (`SN_sha1`) and the digest the PRF row `NID_hmacWithSHA1` resolves to;
 *   * `OBJ_obj2txt(..., 0)` of the `des-ede3-cbc` OID is `DES-EDE3-CBC`, the name
 *     `PKCS5_v2_PBE_keyivgen_ex` builds out of `pbe2->encryption->algorithm` and then fetches.
 *
 * The KDF callbacks record what they were *asked*, and that record is the observation: the two
 * NULL normalisations of `p5_crpt2.c`'s facade, the `passlen == -1` fall-through of
 * `p5_scrypt.c`'s (which does **not** normalise it, so `-1` arrives as `SIZE_MAX`), the iteration
 * count, the digest name, the `pkcs5` mode and the scrypt parameters. The derived key is a
 * function of exactly those, so the cipher's `encrypt_init` record -- the key and IV it received --
 * proves which KDF ran and that its output is what reached the cipher.
 *
 * What is measured, arm by arm
 * ---------------------------
 *   * `EVP_PBE_get` for all thirty-four `builtin_pbe[]` rows in index order, the out-of-range
 *     answer, and the NULL out-parameter pair. The row *order* is the thing a transcription of
 *     `evp_pbe.c` can get wrong in a way nothing else notices.
 *   * `EVP_PBE_find`/`EVP_PBE_find_ex` for each of the thirty-four with the return code, both NID
 *     out-parameters and the two keygen *presence* answers. The PRF and KDF blocks are where the
 *     `-1` sentinels live, and the six rows the authority names `PKCS12_PBE_keyivgen` are the
 *     registered divergence (see below).
 *   * `EVP_PBE_alg_add_type` for all three `pbe_type` arms and for a type the table has none of,
 *     `EVP_PBE_alg_add`'s two `-1` arms, the application registry's precedence over the builtin
 *     table for the *same* key, the plain (non-`_ex`) keygen column reached through
 *     `EVP_PBE_CipherInit_ex`, and `EVP_PBE_cleanup` followed by a find of both kinds of row.
 *   * `PKCS5_PBKDF2_HMAC` and `_SHA1`: the six `OSSL_KDF_PARAM_*` inputs the facade constructs,
 *     `passlen == -1`, a NULL `pass`, a NULL `salt` with a zero length, a NULL salt with a
 *     *non*-zero length (a different rule from `EVP_PBE_scrypt_ex`'s), `iter = 0`, a zero-length
 *     output and a length the implementation refuses.
 *   * `PKCS5_PBE_keyivgen`/`_ex` directly and through
 *     `EVP_PBE_CipherInit_ex(OBJ_nid2obj(NID_pbeWithMD2AndDES_CBC), ...)`, and the two refusals
 *     that precede every derivation.
 *   * `PKCS5_v2_PBE_keyivgen` through a hand-built `PBE2PARAM` and again through
 *     `EVP_PBE_CipherInit_ex(OBJ_nid2obj(NID_pbes2), ...)`; then `PKCS5_v2_PBKDF2_keyivgen`/`_ex`.
 *   * `PKCS5_v2_scrypt_keyivgen`/`_ex` through a hand-built `SCRYPT_PARAMS`: the `EVP_PBE_scrypt_ex`
 *     *probe* call at `p5_scrypt.c:286` shows up as a derivation with no output buffer, so a
 *     success is two derivations and a `:289` refusal is one.
 *   * `PKCS5_PBE_add`, which is empty and must stay callable.
 *
 * Deliberately not observed, each with its coordinate
 * --------------------------------------------------
 *   * **The six `PKCS12_PBE_keyivgen` rows' keygen presence.** `crypto/pkcs12/p12_crpt.c` is
 *     Phase 10's, so the six rows at `evp_pbe.c:46-57` carry no keygen in this build. The rows stay
 *     in the table, so the return code and both NIDs are compared for all six; the two presence
 *     answers are printed as a fixed marker instead, and the difference is
 *     `docs/SECURITY_DIVERGENCE_POLICY.md` **D-PBE-PKCS12-KEYGEN-1**. A probe that printed `NULL`
 *     here would compare a *registered* difference and report it as a residual.
 *   * **`EVP_PBE_CipherInit_ex` on one of those six objects**, which the authority answers by
 *     calling `PKCS12_PBE_keyivgen_ex` and this crate answers 0 for. The boundary is the
 *     `pbe.cipherinit.pkcs12=NOT_MEASURED_REGISTERED_DIVERGENCE` line.
 *   * **A PBE2PARAM whose keyfunc names an application-added KDF row with no `keygen_ex`**, which
 *     faults the authority at `p5_crpt2.c:167` (a call through a NULL `kdf`). Not comparable.
 *   * **More than 64 key bytes**: `PKCS5_v2_PBKDF2_keyivgen_ex`'s `OPENSSL_assert`
 *     (`p5_crpt2.c:200`) is an `OPENSSL_die`, and `PKCS5_v2_scrypt_keyivgen_ex` has no bound test at
 *     all (`p5_scrypt.c:295-300`), so a large key length aborts on one side and overflows on the
 *     other. Fault boundaries, not observations.
 *   * **`PKCS5_v2_PBKDF2_keyivgen`/`_ex` called directly.** Both are declared in
 *     `crypto/evp/evp_local.h`, which is not installed, and the authority's version script keeps
 *     them **local** in `libcrypto.so.3` (`nm` shows `t`, not `T`), so no probe can call either one
 *     and a probe that declared its own prototype would not link. Their *existence* is still
 *     observed -- the `NID_id_pbkdf2` OUTER and KDF rows report `K` and `E` -- and their `_ex` body
 *     is reached through `PKCS5_v2_PBE_keyivgen_ex` and through
 *     `EVP_PBE_CipherInit_ex(OBJ_nid2obj(NID_pbes2), ...)`, which is what the `v2.param` and
 *     `pbe.cipherinit.pbes2` arms are. The plain spelling has no caller on either side: the table
 *     names it in the `keygen` column and every caller prefers `keygen_ex`.
 *   * **`EVP_CIPHER_get_nid` on a fetched provider cipher**, which is what
 *     `EVP_PBE_alg_add`'s cipher read is: the authority answers `NID_des_cbc` for a fetched
 *     `DES-CBC` and this crate answers `NID_undef`, because `set_legacy_nid` consults the *legacy*
 *     method table, whose contents are Phase 13's. `docs/SECURITY_DIVERGENCE_POLICY.md`
 *     **D-EVP-CIPHER-LEGACY-NID-1**; the arm's return code is compared and the two NIDs are the
 *     marker.
 *   * **The raising *line* of the records Phase 5's ASN.1 decoder adds under one refusal.** The
 *     `v2.wrong_shape` arm's chain carries `asn1_template_noexp_d2i`'s nested error, and the
 *     authority raises it at `crypto/asn1/tasn_dec.c:712` where this crate records `:703` -- the
 *     two arms of that function were folded into one epilogue, which keeps the first arm's line.
 *     That is a Phase 5 transcription defect this court measured and did **not** repair (it is
 *     outside this slice's files); it is written up in `docs/DECISIONS.md` D192. The arm prints the
 *     chain's reasons and this slice's own last record's coordinates instead.
 *   * **`EVP_PBE_cleanup` from `EVP_cleanup`** (`crypto/evp/names.c:191`), a real caller whose
 *     effect is the one this probe drives directly.
 *
 * Addresses are never printed. Every observation is a return code, an error-queue record read back
 * as a reason string with the raising function and line, a parameter vector this probe's own
 * callbacks were handed, or the bytes they produced.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>

/* ---- output helpers ---------------------------------------------------------------------- */

/* The whole queue, not only its top: a failed decode appends ASN1's own record *under* the EVP
 * one, and comparing the pair is what makes the two sites at `p5_crpt.c:46` and `:52` -- which
 * share one reason code -- distinguishable. */
static void drain(void)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags, first = 1;

    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        const char *rsn = ERR_reason_error_string(e);

        (void) file;
        if (!first)
            printf(",");
        printf("%s", rsn == NULL ? "<no-string>" : rsn);
        if (data != NULL)
            printf("[%s]", data);
        printf("@%s/%d", func == NULL ? "<no-func>" : func, line);
        first = 0;
    }
    if (first)
        printf("<empty>");
    printf("\n");
    ERR_clear_error();
}

/* Reasons and data only, with no raising coordinates. One arm's queue carries records from
 * `crypto/asn1/tasn_dec.c`'s decoder, which is Phase 5's, and one of its lines is not this slice's
 * to certify; the slice's *own* record in the same chain is compared through `say_top` below. */
static void drain_reasons(void)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags, first = 1;

    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        const char *rsn = ERR_reason_error_string(e);

        (void) file;
        (void) func;
        (void) line;
        if (!first)
            printf(",");
        printf("%s", rsn == NULL ? "<no-string>" : rsn);
        if (data != NULL)
            printf("[%s]", data);
        first = 0;
    }
    if (first)
        printf("<empty>");
    printf("\n");
    ERR_clear_error();
}

/* The newest record's reason together with its raising function and line, read without consuming
 * it: the slice's own refusal is the last thing raised in the chains where this is used. */
static void say_top(const char *key)
{
    const char *file, *func, *data;
    int line, flags;
    unsigned long e = ERR_peek_error_all(&file, &line, &func, &data, &flags);
    const char *rsn = ERR_reason_error_string(e);

    (void) file;
    if (e == 0) {
        printf("%s=<empty>\n", key);
    } else {
        printf("%s=%s", key, rsn == NULL ? "<no-string>" : rsn);
        if (data != NULL)
            printf("[%s]", data);
        printf("@%s/%d\n", func == NULL ? "<no-func>" : func, line);
    }
    ERR_clear_error();
}

static void say_hex(const char *key, const unsigned char *b, size_t n)
{
    size_t i;

    printf("%s=", key);
    if (n == 0) {
        printf("(empty)");
    } else {
        for (i = 0; i < n; i++)
            printf("%02x", b[i]);
    }
    printf(" err=%lu\n", ERR_peek_error());
    ERR_clear_error();
}

/* ---- the probe's provider: three KDFs, two digests, two ciphers ------------------------- */

#define COURT_BUF 96

struct kdf_rec {
    int new_calls, free_calls, derive_calls;
    /* The last derivation's inputs. `pass_seen`/`salt_seen` say whether the parameter was present
     * at all, which is how a normalisation can be told from a missing parameter. */
    int pass_seen, pass_null;
    size_t passlen;
    unsigned char pass[COURT_BUF];
    size_t pass_len;
    int salt_seen, salt_null;
    size_t saltlen;
    unsigned char salt[COURT_BUF];
    size_t salt_len;
    int has_iter;
    long iter;
    int has_pkcs5;
    long pkcs5;
    int has_digest;
    char digest[64];
    size_t outlen;
    int out_null;
    int out_written;
    unsigned char out[COURT_BUF];
    int has_n, has_r, has_p, has_maxmem;
    uint64_t nn, rr, pp, maxmem;
};

/* Index 0 unused; 1 = PBKDF1, 2 = PBKDF2, 3 = SCRYPT, so the transcript names the algorithm by
 * number instead of by pointer. */
static struct kdf_rec rec[4];

struct kdf_ctx {
    int tag;
};

static void *kdf_newctx_tag(void *provctx, int tag)
{
    struct kdf_ctx *d;

    (void) provctx;
    d = malloc(sizeof *d);
    if (d == NULL)
        return NULL;
    d->tag = tag;
    rec[tag].new_calls++;
    return d;
}

static void *kdf1_newctx(void *provctx)
{
    return kdf_newctx_tag(provctx, 1);
}

static void *kdf2_newctx(void *provctx)
{
    return kdf_newctx_tag(provctx, 2);
}

static void *scrypt_newctx(void *provctx)
{
    return kdf_newctx_tag(provctx, 3);
}

static void kdf_freectx(void *kctx)
{
    struct kdf_ctx *d = kctx;

    if (d != NULL && d->tag >= 1 && d->tag <= 3)
        rec[d->tag].free_calls++;
    free(d);
}

static void *kdf_dupctx(void *kctx)
{
    struct kdf_ctx *d = kctx, *to;

    if (d == NULL)
        return NULL;
    to = malloc(sizeof *to);
    if (to == NULL)
        return NULL;
    *to = *d;
    return to;
}

static void get_str_param(const OSSL_PARAM *params, const char *name, char *out, size_t outsz,
                          int *seen)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, name);
    const char *s = NULL;

    *seen = 0;
    out[0] = '\0';
    if (p == NULL)
        return;
    if (OSSL_PARAM_get_utf8_string_ptr(p, &s) && s != NULL) {
        snprintf(out, outsz, "%s", s);
        *seen = 1;
    } else if (OSSL_PARAM_get_utf8_ptr(p, &s) && s != NULL) {
        snprintf(out, outsz, "%s", s);
        *seen = 1;
    }
}

static void get_octet_param(const OSSL_PARAM *params, const char *name,
                            unsigned char *buf, size_t bufsz, size_t *len,
                            int *seen, int *is_null, size_t *shown)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, name);
    const void *ptr = NULL;
    size_t l = 0;

    *seen = 0;
    *is_null = 0;
    *len = 0;
    *shown = (size_t) -3;
    if (p == NULL)
        return;
    *seen = 1;
    if (!OSSL_PARAM_get_octet_string_ptr(p, &ptr, &l)) {
        *shown = (size_t) -2;
        return;
    }
    *is_null = ptr == NULL;
    *shown = l;
    /* The copy is bounded by what this probe can prove is its own: `p5_scrypt.c` forwards a
     * `passlen` of `-1` into a `size_t` (see the module comment), so the length it asks to be read
     * is `SIZE_MAX`. Recording *that* number is the observation; reading it is not. */
    *len = l <= bufsz ? l : 0;
    if (ptr != NULL && *len != 0)
        memcpy(buf, ptr, *len);
}

static void get_u64_param(const OSSL_PARAM *params, const char *name, uint64_t *v, int *seen)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, name);

    *seen = 0;
    if (p != NULL && OSSL_PARAM_get_uint64(p, v))
        *seen = 1;
}

/* One `derive` for the three algorithms: the tag chooses which parameter set is meaningful, and
 * every parameter is recorded whether or not this KDF reads it. */
static int kdf_derive(void *kctx, unsigned char *out, size_t outlen, const OSSL_PARAM *params)
{
    struct kdf_ctx *d = kctx;
    struct kdf_rec *r;
    long v;
    uint64_t fold;
    size_t i;

    if (d == NULL || d->tag < 1 || d->tag > 3)
        return 0;
    r = &rec[d->tag];
    /* A fresh record per call, so a second derivation in the same arm cannot inherit the first
     * one's parameters. The counters and the algorithm name are not per-call. */
    r->derive_calls++;
    r->has_iter = r->has_pkcs5 = r->has_digest = 0;
    r->has_n = r->has_r = r->has_p = r->has_maxmem = 0;
    r->nn = r->rr = r->pp = r->maxmem = 0;
    r->iter = r->pkcs5 = 0;
    r->outlen = outlen;
    r->out_null = out == NULL;
    r->out_written = 0;

    get_octet_param(params, OSSL_KDF_PARAM_PASSWORD, r->pass, sizeof r->pass, &r->pass_len,
                    &r->pass_seen, &r->pass_null, &r->passlen);
    get_octet_param(params, OSSL_KDF_PARAM_SALT, r->salt, sizeof r->salt, &r->salt_len,
                    &r->salt_seen, &r->salt_null, &r->saltlen);
    if (OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER) != NULL) {
        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER);

        if (OSSL_PARAM_get_long(p, &v)) {
            r->iter = v;
            r->has_iter = 1;
        }
    }
    if (OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PKCS5) != NULL) {
        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PKCS5);

        if (OSSL_PARAM_get_long(p, &v)) {
            r->pkcs5 = v;
            r->has_pkcs5 = 1;
        }
    }
    get_str_param(params, OSSL_KDF_PARAM_DIGEST, r->digest, sizeof r->digest, &r->has_digest);
    get_u64_param(params, OSSL_KDF_PARAM_SCRYPT_N, &r->nn, &r->has_n);
    get_u64_param(params, OSSL_KDF_PARAM_SCRYPT_R, &r->rr, &r->has_r);
    get_u64_param(params, OSSL_KDF_PARAM_SCRYPT_P, &r->pp, &r->has_p);
    get_u64_param(params, OSSL_KDF_PARAM_SCRYPT_MAXMEM, &r->maxmem, &r->has_maxmem);

    if (out == NULL)
        return 1;
    if (outlen > sizeof r->out)
        return 0;
    /* A byte pattern rather than a derivation: a function of the recorded inputs, so a reader can
     * see that the value which reached the cipher came from *this* call. */
    fold = (uint64_t) r->pass_len * 131
        + (uint64_t) r->salt_len * 17
        + (uint64_t) (r->has_iter ? r->iter : 0)
        + (uint64_t) r->has_n * 7
        + (uint64_t) d->tag;
    for (i = 0; i < outlen; i++)
        out[i] = (unsigned char) ((fold + i * 7 + d->tag) & 0xff);
    memcpy(r->out, out, outlen);
    r->out_written = 1;
    return 1;
}

static int kdf_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    size_t size = 64;

    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    return 1;
}

static const OSSL_PARAM *kdf_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void) provctx;
    return gettable;
}

static const OSSL_PARAM *kdf_settable_ctx_params(void *kctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_ITER, NULL),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };

    (void) kctx;
    (void) provctx;
    return settable;
}

/* The three tables differ in `newctx` alone, and that is the tag. */
#define KDF_COMMON_FNS                                                        \
    { OSSL_FUNC_KDF_DUPCTX, (void (*)(void)) kdf_dupctx },                    \
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void)) kdf_freectx },                  \
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void)) kdf_derive },                    \
    { OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void)) kdf_get_params },            \
    { OSSL_FUNC_KDF_GETTABLE_PARAMS, (void (*)(void)) kdf_gettable_params },  \
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void)) kdf_settable_ctx_params }

static const OSSL_DISPATCH kdf1_fns[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void)) kdf1_newctx },
    KDF_COMMON_FNS,
    { 0, NULL }
};

static const OSSL_DISPATCH kdf2_fns[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void)) kdf2_newctx },
    KDF_COMMON_FNS,
    { 0, NULL }
};

static const OSSL_DISPATCH kdf_scrypt_fns[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void)) scrypt_newctx },
    KDF_COMMON_FNS,
    { 0, NULL }
};

/* ---- the digest ------------------------------------------------------------------------- */

static int dg_new_calls, dg_init_calls, dg_update_calls, dg_final_calls;

static void *dg_newctx(void *provctx)
{
    static char marker;

    (void) provctx;
    dg_new_calls++;
    return &marker;
}

static void dg_freectx(void *vctx)
{
    (void) vctx;
}

static int dg_init(void *vctx, const OSSL_PARAM params[])
{
    (void) vctx;
    (void) params;
    dg_init_calls++;
    return 1;
}

static int dg_update(void *vctx, const unsigned char *in, size_t inl)
{
    (void) vctx;
    (void) in;
    (void) inl;
    dg_update_calls++;
    return 1;
}

static int dg_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void) vctx;
    (void) out;
    (void) outsz;
    dg_final_calls++;
    if (outl != NULL)
        *outl = 0;
    return 1;
}

/* The size is the method's, so the two digests need two `get_params`. This callback is also what
 * makes the *fetch* succeed: `evp_md_cache_constants` fails it if `size` is unanswered. */
static int dg_get_params_sha1(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);

    if (p != NULL && !OSSL_PARAM_set_size_t(p, 20))
        return 0;
    return 1;
}

static int dg_get_params_md2(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);

    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    return 1;
}

#define DG_FNS(getp)                                                     \
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) dg_newctx },             \
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) dg_freectx },           \
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) dg_init },                 \
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) dg_update },             \
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) dg_final },               \
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) (getp) }

static const OSSL_DISPATCH dg_sha1_fns[] = { DG_FNS(dg_get_params_sha1), { 0, NULL } };
static const OSSL_DISPATCH dg_md2_fns[] = { DG_FNS(dg_get_params_md2), { 0, NULL } };

/*
 * 7.4l. A digest whose `final` actually writes bytes, because `EVP_BytesToKey` is a *loop* over
 * final: the two stubs above answer a length of zero, and the authority's own `for (;;)` would
 * then spin forever -- `nkey` and `niv` never reach zero and `i == mds` on every pass. So this one
 * keeps a twenty-byte state and folds the input into it, which also makes the derived key a
 * function of the probe's own input rather than of a constant. The two sides run the same provider,
 * so any deterministic implementation would do; one whose output *depends* on the input is the one
 * that catches a transcription that passed the wrong pointer or the wrong length.
 */
struct legmd_ctx {
    unsigned char st[20];
};

static void *legmd_newctx(void *provctx)
{
    struct legmd_ctx *d;

    (void) provctx;
    d = malloc(sizeof *d);
    if (d == NULL)
        return NULL;
    memset(d->st, 0, sizeof d->st);
    return d;
}

static void legmd_freectx(void *vctx)
{
    free(vctx);
}

static int legmd_init(void *vctx, const OSSL_PARAM params[])
{
    struct legmd_ctx *d = vctx;

    (void) params;
    memset(d->st, 0, sizeof d->st);
    return 1;
}

static int legmd_update(void *vctx, const unsigned char *in, size_t inl)
{
    struct legmd_ctx *d = vctx;
    size_t i;

    for (i = 0; i < inl; i++)
        d->st[i % sizeof d->st] = (unsigned char) (d->st[i % sizeof d->st] + in[i]
                                                   + (unsigned char) i);
    return 1;
}

static int legmd_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    struct legmd_ctx *d = vctx;
    size_t n = outsz < sizeof d->st ? outsz : sizeof d->st;

    if (out != NULL)
        memcpy(out, d->st, n);
    if (outl != NULL)
        *outl = n;
    return 1;
}

static int legmd_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);

    if (p != NULL && !OSSL_PARAM_set_size_t(p, sizeof(((struct legmd_ctx *) 0)->st)))
        return 0;
    return 1;
}

static const OSSL_DISPATCH legmd_fns[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) legmd_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) legmd_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) legmd_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) legmd_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) legmd_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) legmd_get_params },
    { 0, NULL }
};

/* ---- the cipher ------------------------------------------------------------------------- */

/* The key and IV the last `encrypt_init` was handed: that pair *is* the derived key, so it is the
 * proof that the KDF's output reached the cipher. */
static int ci_einit_calls, ci_dinit_calls;
static unsigned char ci_key[COURT_BUF], ci_iv[COURT_BUF];
static size_t ci_keylen, ci_ivlen;
static int ci_key_null, ci_iv_null;

struct ciph_ctx {
    int keylen;
    int ivlen;
};

static void *ci_newctx_tag(void *provctx, int keylen, int ivlen)
{
    struct ciph_ctx *d;

    (void) provctx;
    d = malloc(sizeof *d);
    if (d == NULL)
        return NULL;
    d->keylen = keylen;
    d->ivlen = ivlen;
    return d;
}

static void *ci8_newctx(void *provctx)
{
    return ci_newctx_tag(provctx, 8, 8);
}

static void *ci24_newctx(void *provctx)
{
    return ci_newctx_tag(provctx, 24, 8);
}

static void ci_freectx(void *cctx)
{
    free(cctx);
}

static void ci_record(const unsigned char *key, size_t keylen, const unsigned char *iv,
                      size_t ivlen)
{
    ci_key_null = key == NULL;
    ci_iv_null = iv == NULL;
    ci_keylen = keylen < sizeof ci_key ? keylen : sizeof ci_key;
    if (key != NULL)
        memcpy(ci_key, key, ci_keylen);
    ci_ivlen = ivlen < sizeof ci_iv ? ivlen : sizeof ci_iv;
    if (iv != NULL)
        memcpy(ci_iv, iv, ci_ivlen);
}

static int ci_encrypt_init(void *cctx, const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    (void) cctx;
    (void) params;
    ci_einit_calls++;
    ci_record(key, keylen, iv, ivlen);
    return 1;
}

static int ci_decrypt_init(void *cctx, const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    (void) cctx;
    (void) params;
    ci_dinit_calls++;
    ci_record(key, keylen, iv, ivlen);
    return 1;
}

static int ci_update(void *cctx, unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl)
{
    (void) cctx;
    (void) out;
    (void) outsize;
    (void) in;
    *outl = inl;
    return 1;
}

static int ci_final(void *cctx, unsigned char *out, size_t *outl, size_t outsize)
{
    (void) cctx;
    (void) out;
    (void) outsize;
    *outl = 0;
    return 1;
}

static int ci_get_params_common(OSSL_PARAM params[], size_t keylen)
{
    OSSL_PARAM *p;
    size_t blksz = 8, ivlen = 8;
    unsigned int mode = EVP_CIPH_CBC_MODE;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode))
        return 0;
    return 1;
}

static int ci_get_params_8(OSSL_PARAM params[])
{
    return ci_get_params_common(params, 8);
}

static int ci_get_params_24(OSSL_PARAM params[])
{
    return ci_get_params_common(params, 24);
}

/* `EVP_CIPHER_CTX_get_key_length` and `_get_iv_length` ask *this* for a provider cipher whose
 * context has no cached length -- by the same rule, in both implementations -- so the two keygens
 * that read a length off a context depend on it. */
static int ci_get_ctx_params(void *cctx, OSSL_PARAM params[])
{
    struct ciph_ctx *d = cctx;
    OSSL_PARAM *p;

    if (d == NULL)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, (size_t) d->keylen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, (size_t) d->ivlen))
        return 0;
    return 1;
}

static const OSSL_PARAM *ci_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_END
    };

    (void) cctx;
    (void) provctx;
    return gettable;
}

#define CI_FNS(newctx, getp)                                                  \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) (newctx) },                   \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) ci_freectx },                \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) ci_encrypt_init },      \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) ci_decrypt_init },      \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) ci_update },                  \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) ci_final },                    \
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) (getp) },                 \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) ci_get_ctx_params },  \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void)) ci_gettable_ctx_params }

static const OSSL_DISPATCH ci8_fns[] = { CI_FNS(ci8_newctx, ci_get_params_8), { 0, NULL } };
static const OSSL_DISPATCH ci24_fns[] = { CI_FNS(ci24_newctx, ci_get_params_24), { 0, NULL } };

/* ---- the provider ----------------------------------------------------------------------- */

static const OSSL_ALGORITHM court_kdfs[] = {
    { "PBKDF1", "provider=court", kdf1_fns, "court pbkdf1" },
    { "PBKDF2", "provider=court", kdf2_fns, "court pbkdf2" },
    { "SCRYPT", "provider=court", kdf_scrypt_fns, "court scrypt" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM court_digests[] = {
    { "SHA1", "provider=court", dg_sha1_fns, "court sha1" },
    { "MD2", "provider=court", dg_md2_fns, "court md2" },
    { "LEG-MD", "provider=court", legmd_fns, "a digest whose final writes bytes, for EVP_BytesToKey" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM court_ciphers[] = {
    { "DES-CBC", "provider=court", ci8_fns, "court des-cbc" },
    { "DES-EDE3-CBC", "provider=court", ci24_fns, "court des-ede3-cbc" },
    { NULL, NULL, NULL, NULL }
};

static char court_marker;

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KDF)
        return court_kdfs;
    if (operation_id == OSSL_OP_DIGEST)
        return court_digests;
    if (operation_id == OSSL_OP_CIPHER)
        return court_ciphers;
    return NULL;
}

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_query },
    { 0, NULL }
};

static int court_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_dispatch;
    *provctx = &court_marker;
    return 1;
}

/* ---- the recorded vectors, as transcript lines ------------------------------------------ */

static void say_kdf(const char *prefix, int tag)
{
    struct kdf_rec *k = &rec[tag];
    char key[80];

    snprintf(key, sizeof key, "%s.activity", prefix);
    printf("%s=%d,%d,%d err=%lu\n", key, k->new_calls, k->free_calls, k->derive_calls,
           ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.pass", prefix);
    say_hex(key, k->pass, k->pass_len);
    snprintf(key, sizeof key, "%s.pass_seen", prefix);
    printf("%s=%d,null=%d,shown=%lu err=%lu\n", key, k->pass_seen, k->pass_null,
           (unsigned long) k->passlen, ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.salt", prefix);
    say_hex(key, k->salt, k->salt_len);
    snprintf(key, sizeof key, "%s.salt_seen", prefix);
    printf("%s=%d,null=%d,shown=%lu err=%lu\n", key, k->salt_seen, k->salt_null,
           (unsigned long) k->saltlen, ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.iter", prefix);
    printf("%s=%d,%ld err=%lu\n", key, k->has_iter, k->iter, ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.pkcs5", prefix);
    printf("%s=%d,%ld err=%lu\n", key, k->has_pkcs5, k->pkcs5, ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.digest", prefix);
    printf("%s=%s err=%lu\n", key, k->has_digest ? k->digest : "(absent)", ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.out", prefix);
    printf("%s=len=%lu,null=%d err=%lu\n", key, (unsigned long) k->outlen, k->out_null,
           ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.derived", prefix);
    if (k->out_written) {
        say_hex(key, k->out, k->outlen);
    } else if (k->out_null) {
        printf("%s=(probe,no_output) err=%lu\n", key, ERR_peek_error());
        ERR_clear_error();
    } else {
        printf("%s=(refused) err=%lu\n", key, ERR_peek_error());
        ERR_clear_error();
    }
    snprintf(key, sizeof key, "%s.scrypt", prefix);
    printf("%s=n=%d:%llu,r=%d:%llu,p=%d:%llu,maxmem=%d:%llu err=%lu\n", key,
           k->has_n, (unsigned long long) k->nn, k->has_r, (unsigned long long) k->rr,
           k->has_p, (unsigned long long) k->pp, k->has_maxmem,
           (unsigned long long) k->maxmem, ERR_peek_error());
    ERR_clear_error();
}

static void reset_records(void)
{
    memset(rec, 0, sizeof rec);
    ci_einit_calls = ci_dinit_calls = 0;
    ci_keylen = ci_ivlen = 0;
    ci_key_null = ci_iv_null = 0;
    dg_new_calls = dg_init_calls = dg_update_calls = dg_final_calls = 0;
    ERR_clear_error();
}

static void say_cipher(const char *prefix)
{
    char key[80];

    snprintf(key, sizeof key, "%s.einit_calls", prefix);
    printf("%s=%d err=%lu\n", key, ci_einit_calls, ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.key", prefix);
    say_hex(key, ci_key, ci_keylen);
    snprintf(key, sizeof key, "%s.key_seen", prefix);
    printf("%s=null=%d,len=%lu err=%lu\n", key, ci_key_null, (unsigned long) ci_keylen,
           ERR_peek_error());
    ERR_clear_error();
    snprintf(key, sizeof key, "%s.iv", prefix);
    say_hex(key, ci_iv, ci_ivlen);
    snprintf(key, sizeof key, "%s.iv_seen", prefix);
    printf("%s=null=%d,len=%lu err=%lu\n", key, ci_iv_null, (unsigned long) ci_ivlen,
           ERR_peek_error());
    ERR_clear_error();
}

/* ---- the ASN.1 parameters --------------------------------------------------------------- */

/*
 * Both parameters this probe needs are *fixed*, because no public constructor builds either of
 * them: `ASN1_TYPE_set_int_octetstring` writes its INTEGER first (`asn1_int_oct`, `evp_asn1.c:87`),
 * where `PBEPARAM` and `PBKDF2PARAM` want the OCTET STRING first, and nothing public builds a
 * `PBE2PARAM` or a `SCRYPT_PARAMS` at all. So each is a literal with its bytes named.
 *
 *     PBEPARAM / PBKDF2PARAM (no keylength, no prf):
 *       30 08                      SEQUENCE, 8 content bytes
 *          04 03 73 61 6c         OCTET STRING "sal"
 *          02 01 03               INTEGER 3
 */
static const unsigned char pbeparam_der[] = {
    0x30, 0x08,
    0x04, 0x03, 's', 'a', 'l',
    0x02, 0x01, 0x03
};

/*
 *     SCRYPT_PARAMS, no keyLength:
 *       30 0e                      SEQUENCE, 14 content bytes
 *          04 03 73 61 6c         OCTET STRING "sal"
 *          02 01 10               INTEGER 16     costParameter (N)
 *          02 01 01               INTEGER 1      blockSize (r)
 *          02 01 01               INTEGER 1      parallelizationParameter (p)
 *     and the same with `02 01 18` (INTEGER 24) appended as keyLength, which makes the content 17.
 */
static const unsigned char scrypt_params_der[] = {
    0x30, 0x0e,
    0x04, 0x03, 's', 'a', 'l',
    0x02, 0x01, 0x10,
    0x02, 0x01, 0x01,
    0x02, 0x01, 0x01
};

static const unsigned char scrypt_params_der_keylen[] = {
    0x30, 0x11,
    0x04, 0x03, 's', 'a', 'l',
    0x02, 0x01, 0x10,
    0x02, 0x01, 0x01,
    0x02, 0x01, 0x01,
    0x02, 0x01, 0x18
};

/*
 *     PBE2PARAM:
 *       30 2d                                     SEQUENCE, 45 content bytes
 *          30 15                                  keyfunc AlgorithmIdentifier, 21 bytes
 *             06 09 2a 86 48 86 f7 0d 01 05 0c        OID id-PBKDF2 (1.2.840.113549.1.5.12)
 *             30 08                                   PBKDF2PARAM, 8 bytes
 *                04 03 73 61 6c                          salt "sal"
 *                02 01 01                                iter 1
 *          30 14                                  encryption AlgorithmIdentifier, 20 bytes
 *             06 08 2a 86 48 86 f7 0d 03 07           OID des-ede3-cbc (1.2.840.113549.3.7)
 *             04 08 <8 bytes>                        the IV parameter
 *
 * The IV is the only variable, so the array is the prefix below with eight bytes appended.
 */
static const unsigned char pbe2_prefix[] = {
    0x30, 0x2d,
    0x30, 0x15,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c,
    0x30, 0x08,
    0x04, 0x03, 's', 'a', 'l',
    0x02, 0x01, 0x01,
    0x30, 0x14,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07,
    0x04, 0x08
};

static ASN1_TYPE *der_to_type(const unsigned char *der, size_t len)
{
    const unsigned char *p = der;

    return d2i_ASN1_TYPE(NULL, &p, (long) len);
}

/* ---- the suite -------------------------------------------------------------------------- */

static OSSL_LIB_CTX *gctx;
static OSSL_LIB_CTX *gprev;
static OSSL_PROVIDER *gprov;

static int install_provider(void)
{
    gctx = OSSL_LIB_CTX_new();
    if (gctx == NULL)
        return 0;
    if (!OSSL_PROVIDER_add_builtin(gctx, "court-pbe", court_provider_init))
        return 0;
    gprov = OSSL_PROVIDER_load(gctx, "court-pbe");
    if (gprov == NULL)
        return 0;
    gprev = OSSL_LIB_CTX_set0_default(gctx);
    return 1;
}

/* The six NIDs whose keygen is `PKCS12_PBE_keyivgen` in the authority: the registered
 * divergence. */
static int is_pkcs12_row(int nid)
{
    return nid == 144 || nid == 145 || nid == 146 || nid == 147 || nid == 148 || nid == 149;
}

int main(void)
{
    EVP_CIPHER *cipher8, *cipher24;
    EVP_MD *md_sha1, *md_md2, *md_leg;
    ASN1_TYPE *pbeparam, *wrong_type, *pbe2_param, *scrypt_param, *scrypt_param_kl;
    unsigned char pbe2_der[sizeof pbe2_prefix + 8];
    unsigned char salt[] = { 's', 'a', 'l' };
    unsigned char out[128];
    int i, type, id, rc, pcnid, pmnid;
    EVP_PBE_KEYGEN *kg;
    EVP_PBE_KEYGEN_EX *kgx;
    EVP_CIPHER_CTX *cctx;
    const int app_nid = 50000;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (!install_provider()) {
        printf("setup.provider=0 err=%lu\n", ERR_peek_error());
        return 0;
    }
    printf("setup.provider=1 err=%lu\n", ERR_peek_error());
    ERR_clear_error();

    md_sha1 = EVP_MD_fetch(gctx, "SHA1", NULL);
    md_md2 = EVP_MD_fetch(gctx, "MD2", NULL);
    md_leg = EVP_MD_fetch(gctx, "LEG-MD", NULL);
    cipher8 = EVP_CIPHER_fetch(gctx, "DES-CBC", NULL);
    cipher24 = EVP_CIPHER_fetch(gctx, "DES-EDE3-CBC", NULL);
    printf("setup.digests=%d,%d err=%lu\n", md_sha1 != NULL, md_md2 != NULL, ERR_peek_error());
    ERR_clear_error();
    printf("setup.ciphers=%d,%d err=%lu\n", cipher8 != NULL, cipher24 != NULL, ERR_peek_error());
    ERR_clear_error();
    if (md_sha1 == NULL || md_md2 == NULL || md_leg == NULL || cipher8 == NULL || cipher24 == NULL) {
        printf("setup.aborted=1 err=%lu\n", ERR_peek_error());
        return 0;
    }

    /*
     * ---- `EVP_PBE_get`: the table, row by row --------------------------------------------
     */
    for (i = 0; i < 34; i++) {
        type = -1;
        id = -1;
        rc = EVP_PBE_get(&type, &id, (size_t) i);
        printf("pbe.get.%02d=%d,%d,%d err=%lu\n", i, rc, type, id, ERR_peek_error());
        ERR_clear_error();
    }
    type = -1;
    id = -1;
    rc = EVP_PBE_get(&type, &id, 34);
    printf("pbe.get.oob=%d,%d,%d err=%lu\n", rc, type, id, ERR_peek_error());
    ERR_clear_error();
    rc = EVP_PBE_get(NULL, NULL, 0);
    printf("pbe.get.nulls=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();

    /*
     * ---- `EVP_PBE_find_ex`/`EVP_PBE_find` for every row ----------------------------------
     */
    for (i = 0; i < 34; i++) {
        int pk;

        type = -1;
        id = -1;
        (void) EVP_PBE_get(&type, &id, (size_t) i);
        pcnid = 12345;
        pmnid = 12345;
        kg = NULL;
        kgx = NULL;
        rc = EVP_PBE_find_ex(type, id, &pcnid, &pmnid, &kg, &kgx);
        if (is_pkcs12_row(id)) {
            printf("pbe.find.%02d=%d,%d,%d,%d,%d,NOT_MEASURED_REGISTERED_DIVERGENCE err=%lu\n",
                   i, rc, type, id, pcnid, pmnid, ERR_peek_error());
        } else {
            printf("pbe.find.%02d=%d,%d,%d,%d,%d,%s,%s err=%lu\n", i, rc, type, id,
                   pcnid, pmnid, kg != NULL ? "K" : "-", kgx != NULL ? "E" : "-",
                   ERR_peek_error());
        }
        ERR_clear_error();
        pcnid = 12345;
        pmnid = 12345;
        kg = NULL;
        pk = EVP_PBE_find(type, id, &pcnid, &pmnid, &kg);
        if (is_pkcs12_row(id)) {
            printf("pbe.find_plain.%02d=%d,%d,%d,NOT_MEASURED_REGISTERED_DIVERGENCE err=%lu\n",
                   i, pk, pcnid, pmnid, ERR_peek_error());
        } else {
            printf("pbe.find_plain.%02d=%d,%d,%d,%s err=%lu\n", i, pk, pcnid, pmnid,
                   kg != NULL ? "K" : "-", ERR_peek_error());
        }
        ERR_clear_error();
    }

    pcnid = 1;
    pmnid = 1;
    kg = NULL;
    rc = EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_undef, &pcnid, &pmnid, &kg);
    printf("pbe.find.undef=%d,%d,%d err=%lu\n", rc, pcnid, pmnid, ERR_peek_error());
    ERR_clear_error();
    pcnid = 1;
    pmnid = 1;
    rc = EVP_PBE_find(EVP_PBE_TYPE_OUTER, 424242, &pcnid, &pmnid, &kg);
    printf("pbe.find.unknown=%d,%d,%d err=%lu\n", rc, pcnid, pmnid, ERR_peek_error());
    ERR_clear_error();
    pcnid = 1;
    pmnid = 1;
    rc = EVP_PBE_find(EVP_PBE_TYPE_KDF, NID_hmacWithSHA1, &pcnid, &pmnid, &kg);
    printf("pbe.find.wrong_type=%d,%d,%d err=%lu\n", rc, pcnid, pmnid, ERR_peek_error());
    ERR_clear_error();
    rc = EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndDES_CBC, NULL, NULL, NULL, NULL);
    printf("pbe.find.nulls=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();

    /*
     * ---- the application registry --------------------------------------------------------
     *
     * Three added rows, one per `pbe_type`, and one whose type the builtin table has none of: the
     * authority stores the type verbatim and finds the row back under that same number, so an
     * unknown type is *accepted* here rather than refused.
     */
    rc = EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, app_nid, 7, 8, PKCS5_PBE_keyivgen);
    printf("pbe.add.outer=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();
    rc = EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, app_nid + 1, -1, 9, PKCS5_PBE_keyivgen);
    printf("pbe.add.prf=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();
    rc = EVP_PBE_alg_add_type(EVP_PBE_TYPE_KDF, app_nid + 2, -1, -1, PKCS5_PBE_keyivgen);
    printf("pbe.add.kdf=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();
    rc = EVP_PBE_alg_add_type(99, app_nid + 3, -1, -1, PKCS5_PBE_keyivgen);
    printf("pbe.add.odd_type=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();

    {
        const int types[4] = { EVP_PBE_TYPE_OUTER, EVP_PBE_TYPE_PRF, EVP_PBE_TYPE_KDF, 99 };

        for (i = 0; i < 4; i++) {
            pcnid = 0;
            pmnid = 0;
            kg = NULL;
            kgx = NULL;
            rc = EVP_PBE_find_ex(types[i], app_nid + i, &pcnid, &pmnid, &kg, &kgx);
            printf("pbe.added.%d=%d,%d,%d,%s,%s err=%lu\n", i, rc, pcnid, pmnid,
                   kg != NULL ? "K" : "-", kgx != NULL ? "E" : "-", ERR_peek_error());
            ERR_clear_error();
        }
    }

    /* `EVP_PBE_alg_add` reads a `-1` out of a NULL cipher and a NULL digest. */
    rc = EVP_PBE_alg_add(app_nid + 10, NULL, NULL, NULL);
    printf("pbe.alg_add.nulls=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();
    pcnid = 0;
    pmnid = 0;
    kg = NULL;
    rc = EVP_PBE_find(EVP_PBE_TYPE_OUTER, app_nid + 10, &pcnid, &pmnid, &kg);
    printf("pbe.alg_add.nulls_find=%d,%d,%d,%s err=%lu\n", rc, pcnid, pmnid,
           kg != NULL ? "K" : "-", ERR_peek_error());
    ERR_clear_error();

    /* A row whose NID is a *cipher* NID, which no builtin OUTER row holds, so nothing is shadowed
     * and `EVP_PBE_CipherInit_ex` can be driven against it -- the only way to reach the table's
     * **plain** `keygen` column, since `alg_add_type` leaves `keygen_ex` empty. The NIDs are given
     * explicitly rather than read out of the fetched methods: `EVP_CIPHER_get_nid` on a fetched
     * provider cipher is the registered divergence below. */
    rc = EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, NID_des_ede3_cbc, NID_des_cbc, NID_md2,
                              PKCS5_PBE_keyivgen);
    printf("pbe.alg_add.row=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();
    pcnid = 0;
    pmnid = 0;
    kg = NULL;
    rc = EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_des_ede3_cbc, &pcnid, &pmnid, &kg);
    printf("pbe.alg_add.row_find=%d,%d,%d,%s err=%lu\n", rc, pcnid, pmnid,
           kg != NULL ? "K" : "-", ERR_peek_error());
    ERR_clear_error();

    /* `EVP_PBE_alg_add` reads both NIDs out of the methods it is handed, and the *cipher* read is
     * where the register entry lands: the authority answers `NID_des_cbc` and this crate answers
     * `NID_undef`, because the legacy method table `set_legacy_nid` consults is Phase 13's. The
     * call is driven and its return code compared; the two NIDs it stored are not, and the
     * boundary's own line names the entry. */
    rc = EVP_PBE_alg_add(NID_rc4, cipher8, md_md2, PKCS5_PBE_keyivgen);
    printf("pbe.alg_add.methods=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();
    printf("pbe.alg_add.methods_nids=NOT_COMPARED_REGISTERED_DIVERGENCE_D_EVP_CIPHER_LEGACY_NID_1\n");

    pbeparam = der_to_type(pbeparam_der, sizeof pbeparam_der);
    wrong_type = ASN1_TYPE_new();
    printf("pbeparam.build=%d,%d err=%lu\n", pbeparam != NULL, wrong_type != NULL,
           ERR_peek_error());
    ERR_clear_error();

    cctx = EVP_CIPHER_CTX_new();
    printf("pbeparam.ctx=%d err=%lu\n", cctx != NULL, ERR_peek_error());
    ERR_clear_error();
    reset_records();
    rc = EVP_PBE_CipherInit_ex(OBJ_nid2obj(NID_des_ede3_cbc), "pw", -1, pbeparam, cctx, 1, gctx,
                               NULL);
    printf("pbe.cipherinit.approw=%d err=", rc);
    drain();
    say_kdf("pbe.cipherinit.approw_kdf", 1);
    say_cipher("pbe.cipherinit.approw");

    /* The same key as a builtin row: the application registry is searched first, so the added row
     * shadows it. `EVP_PBE_get` still answers the builtin row, because it reads the table. */
    rc = EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndDES_CBC, 999, 998, NULL);
    printf("pbe.add.shadow=%d err=%lu\n", rc, ERR_peek_error());
    ERR_clear_error();
    pcnid = 0;
    pmnid = 0;
    kg = NULL;
    rc = EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndDES_CBC, &pcnid, &pmnid, &kg);
    printf("pbe.shadowed=%d,%d,%d,%s err=%lu\n", rc, pcnid, pmnid, kg != NULL ? "K" : "-",
           ERR_peek_error());
    ERR_clear_error();
    type = -1;
    id = -1;
    rc = EVP_PBE_get(&type, &id, 1);
    printf("pbe.shadowed.get=%d,%d,%d err=%lu\n", rc, type, id, ERR_peek_error());
    ERR_clear_error();

    /*
     * `EVP_PBE_cleanup` releases the application registry and clears the pointer. The builtin rows
     * are not its business: a find of one still answers, and a find of an added one does not. A
     * second call is a no-op.
     */
    EVP_PBE_cleanup();
    ERR_clear_error();
    pcnid = 0;
    pmnid = 0;
    rc = EVP_PBE_find(EVP_PBE_TYPE_OUTER, app_nid, &pcnid, &pmnid, NULL);
    printf("pbe.cleanup.added=%d,%d,%d err=%lu\n", rc, pcnid, pmnid, ERR_peek_error());
    ERR_clear_error();
    pcnid = 0;
    pmnid = 0;
    rc = EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndDES_CBC, &pcnid, &pmnid, NULL);
    printf("pbe.cleanup.builtin=%d,%d,%d err=%lu\n", rc, pcnid, pmnid, ERR_peek_error());
    ERR_clear_error();
    EVP_PBE_cleanup();
    printf("pbe.cleanup.idempotent=1 err=%lu\n", ERR_peek_error());
    ERR_clear_error();

    /* `PKCS5_PBE_add` is empty in the authority and empty here, and must stay callable. */
    PKCS5_PBE_add();
    PKCS5_PBE_add();
    printf("pkcs5.add.called=1 err=%lu\n", ERR_peek_error());
    ERR_clear_error();

    /*
     * ---- `PKCS5_PBKDF2_HMAC` and `_SHA1` --------------------------------------------------
     */
    reset_records();
    memset(out, 0xEE, sizeof out);
    rc = PKCS5_PBKDF2_HMAC("pw", -1, salt, 3, 4, md_sha1, 16, out);
    printf("pbkdf2.plain=%d err=", rc);
    drain();
    say_kdf("pbkdf2.plain_kdf", 2);
    say_hex("pbkdf2.plain_out", out, 16);
    printf("pbkdf2.plain_beyond=%d err=%lu\n", out[16] == 0xEE, ERR_peek_error());
    ERR_clear_error();

    reset_records();
    rc = PKCS5_PBKDF2_HMAC(NULL, 0, NULL, 0, 0, md_sha1, 0, out);
    printf("pbkdf2.null_zero=%d err=", rc);
    drain();
    say_kdf("pbkdf2.null_zero_kdf", 2);

    /* The `else if (passlen == -1)` is not a second `if`, so a NULL pass with -1 never reaches the
     * `strlen`. */
    reset_records();
    rc = PKCS5_PBKDF2_HMAC(NULL, -1, NULL, 0, 3, md_sha1, 8, out);
    printf("pbkdf2.null_pass_neg=%d err=", rc);
    drain();
    say_kdf("pbkdf2.null_pass_neg_kdf", 2);

    /* A NULL salt with a *non-zero* length: a different rule from `EVP_PBE_scrypt_ex`'s, which
     * normalises the length whenever the pointer is NULL. */
    reset_records();
    rc = PKCS5_PBKDF2_HMAC("pw", 2, NULL, 5, 3, md_sha1, 8, out);
    printf("pbkdf2.null_salt_len=%d err=", rc);
    drain();
    say_kdf("pbkdf2.null_salt_len_kdf", 2);

    /* A length the implementation refuses: `EVP_KDF_derive`'s answer is the facade's. */
    reset_records();
    rc = PKCS5_PBKDF2_HMAC("pw", 2, salt, 3, 1, md_sha1, 97, out);
    printf("pbkdf2.too_long=%d err=", rc);
    drain();
    say_kdf("pbkdf2.too_long_kdf", 2);

    /* The SHA1 spelling fetches its digest and then runs the same path. */
    reset_records();
    rc = PKCS5_PBKDF2_HMAC_SHA1("pw", -1, salt, 3, 2, 12, out);
    printf("pbkdf2.sha1=%d err=", rc);
    drain();
    say_kdf("pbkdf2.sha1_kdf", 2);
    say_hex("pbkdf2.sha1_out", out, 12);
    printf("pbkdf2.digest_activity=%d,%d,%d,%d err=%lu\n", dg_new_calls, dg_init_calls,
           dg_update_calls, dg_final_calls, ERR_peek_error());
    ERR_clear_error();

    /*
     * ---- the v1 keygen -------------------------------------------------------------------
     */
    reset_records();
    rc = PKCS5_PBE_keyivgen_ex(cctx, "pw", -1, pbeparam, cipher8, md_md2, 1, gctx, NULL);
    printf("pbeparam.ex=%d err=", rc);
    drain();
    say_kdf("pbeparam.kdf", 1);
    say_cipher("pbeparam");

    /* The plain spelling, whose NULL libctx resolves through this probe's thread default. */
    reset_records();
    rc = PKCS5_PBE_keyivgen(cctx, "pw", -1, pbeparam, cipher8, md_md2, 0);
    printf("pbeparam.plain=%d err=", rc);
    drain();
    say_kdf("pbeparam.plain_kdf", 1);
    say_cipher("pbeparam.plain");

    /* The two refusals before any derivation, each with its own site: a NULL parameter and a
     * value that is not a SEQUENCE. Both carry `EVP_R_DECODE_ERROR`, which is why the transcript
     * prints the raising line as well as the reason. */
    reset_records();
    rc = PKCS5_PBE_keyivgen_ex(cctx, "pw", -1, NULL, cipher8, md_md2, 1, gctx, NULL);
    printf("pbeparam.null_param=%d err=", rc);
    drain();
    reset_records();
    rc = PKCS5_PBE_keyivgen_ex(cctx, "pw", -1, wrong_type, cipher8, md_md2, 1, gctx, NULL);
    printf("pbeparam.wrong_type=%d err=", rc);
    drain();

    /* `EVP_PBE_CipherInit_ex` on the `pbeWithMD2AndDES_CBC` object: the only path that reaches the
     * table's keygen columns. It fetches `DES-CBC` and `MD2` by NID -- this probe's provider -- and
     * calls `PKCS5_PBE_keyivgen_ex`, so the KDF and cipher records are evidence that the *table*
     * chose this keygen. */
    reset_records();
    rc = EVP_PBE_CipherInit_ex(OBJ_nid2obj(NID_pbeWithMD2AndDES_CBC), "pw", -1, pbeparam, cctx, 1,
                               gctx, NULL);
    printf("pbe.cipherinit.v1=%d err=", rc);
    drain();
    say_kdf("pbe.cipherinit.v1_kdf", 1);
    say_cipher("pbe.cipherinit.v1");

    reset_records();
    rc = EVP_PBE_CipherInit(OBJ_nid2obj(NID_pbeWithMD2AndDES_CBC), "pw", -1, pbeparam, cctx, 1);
    printf("pbe.cipherinit.v1_plain=%d err=", rc);
    drain();
    say_kdf("pbe.cipherinit.v1_plain_kdf", 1);
    say_cipher("pbe.cipherinit.v1_plain");

    /* A NULL object, and an object whose NID the table has no OUTER row of. */
    reset_records();
    rc = EVP_PBE_CipherInit(NULL, "pw", -1, pbeparam, cctx, 1);
    printf("pbe.cipherinit.null_obj=%d err=", rc);
    drain();
    reset_records();
    rc = EVP_PBE_CipherInit(OBJ_nid2obj(NID_sha1), "pw", -1, pbeparam, cctx, 1);
    printf("pbe.cipherinit.no_row=%d err=", rc);
    drain();
    EVP_CIPHER_CTX_free(cctx);
    ERR_clear_error();

    /*
     * ---- the two v2 keygens ----------------------------------------------------------------
     */
    memcpy(pbe2_der, pbe2_prefix, sizeof pbe2_prefix);
    memset(pbe2_der + sizeof pbe2_prefix, 0x5a, 8);
    pbe2_param = der_to_type(pbe2_der, sizeof pbe2_der);
    scrypt_param = der_to_type(scrypt_params_der, sizeof scrypt_params_der);
    scrypt_param_kl = der_to_type(scrypt_params_der_keylen, sizeof scrypt_params_der_keylen);
    printf("v2param.build=%d,%d,%d err=%lu\n", pbe2_param != NULL, scrypt_param != NULL,
           scrypt_param_kl != NULL, ERR_peek_error());
    ERR_clear_error();

    cctx = EVP_CIPHER_CTX_new();
    reset_records();
    rc = PKCS5_v2_PBE_keyivgen_ex(cctx, "pw", -1, pbe2_param, NULL, NULL, 1, gctx, NULL);
    printf("v2.param=%d err=", rc);
    drain();
    say_kdf("v2.param_kdf", 2);
    say_cipher("v2.param");

    reset_records();
    rc = PKCS5_v2_PBE_keyivgen(cctx, "pw", -1, pbe2_param, NULL, NULL, 0);
    printf("v2.plain=%d err=", rc);
    drain();
    say_kdf("v2.plain_kdf", 2);
    say_cipher("v2.plain");

    /* Through the table: the `pbes2` row's keygen is `PKCS5_v2_PBE_keyivgen`, which is the only
     * caller of the KDF row's keygen. */
    reset_records();
    rc = EVP_PBE_CipherInit_ex(OBJ_nid2obj(NID_pbes2), "pw", -1, pbe2_param, cctx, 1, gctx, NULL);
    printf("pbe.cipherinit.pbes2=%d err=", rc);
    drain();
    say_kdf("pbe.cipherinit.pbes2_kdf", 2);
    say_cipher("pbe.cipherinit.pbes2");

    /* A PBE2PARAM whose keyfunc OID the object database does not know: the KDF lookup is the
     * refusal, and it happens before the cipher is fetched. */
    reset_records();
    rc = PKCS5_v2_PBE_keyivgen_ex(cctx, "pw", -1, pbeparam, NULL, NULL, 1, gctx, NULL);
    printf("v2.wrong_shape=%d err=", rc);
    say_top("v2.wrong_shape.top");
    drain_reasons();
    EVP_CIPHER_CTX_free(cctx);
    ERR_clear_error();

    /*
     * ---- the scrypt keygen ------------------------------------------------------------------
     */
    cctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(cctx, cipher24, NULL, NULL, NULL, 1);
    ERR_clear_error();
    reset_records();
    rc = PKCS5_v2_scrypt_keyivgen_ex(cctx, "pw", -1, scrypt_param, NULL, NULL, 1, gctx, NULL);
    printf("scrypt.param=%d err=", rc);
    drain();
    say_kdf("scrypt.param_kdf", 3);
    say_cipher("scrypt.param");

    /* The same shape with `keyLength` present and equal to the context's 24: accepted. */
    reset_records();
    rc = PKCS5_v2_scrypt_keyivgen(cctx, "pw", -1, scrypt_param_kl, NULL, NULL, 1);
    printf("scrypt.keylen_ok=%d err=", rc);
    drain();
    say_kdf("scrypt.keylen_ok_kdf", 3);

    /* A context whose cipher reports 8 bytes against a `keyLength` of 24: refused at `:278`,
     * before either scrypt call. */
    EVP_CipherInit_ex(cctx, cipher8, NULL, NULL, NULL, 1);
    ERR_clear_error();
    reset_records();
    rc = PKCS5_v2_scrypt_keyivgen_ex(cctx, "pw", -1, scrypt_param_kl, NULL, NULL, 1, gctx, NULL);
    printf("scrypt.keylen_mismatch=%d err=", rc);
    drain();
    say_kdf("scrypt.keylen_mismatch_kdf", 3);

    /* Without `keyLength` the context's own length is used, so the eight-byte cipher is keyed with
     * eight bytes out of the same SCRYPT_PARAMS. */
    reset_records();
    rc = PKCS5_v2_scrypt_keyivgen_ex(cctx, "pw", -1, scrypt_param, NULL, NULL, 1, gctx, NULL);
    printf("scrypt.keylen8=%d err=", rc);
    drain();
    say_kdf("scrypt.keylen8_kdf", 3);
    say_cipher("scrypt.keylen8");

    /* A NULL parameter on an armed context is the second refusal. */
    reset_records();
    rc = PKCS5_v2_scrypt_keyivgen_ex(cctx, "pw", -1, NULL, NULL, NULL, 1, gctx, NULL);
    printf("scrypt.null_param=%d err=", rc);
    drain();

    EVP_CIPHER_CTX_free(cctx);
    ERR_clear_error();

    /*
     * ---- `EVP_BytesToKey` (7.4l) -------------------------------------------------------
     *
     * The digest is `LEG-MD`, whose `final` writes twenty bytes: the authority's loop is infinite
     * with a zero-length digest, so a stub could not be used. The salt is exactly `PKCS5_SALT_LEN`
     * because that is how much the function reads, and the cipher is the eight-byte one whose
     * `key + iv` (16) fits inside a single digest block, and the twenty-four-byte one whose `24 + 8`
     * does not and forces the outer loop's second round. Every arm prints the raw key and IV,
     * because a transcription that fed the wrong pointer or the wrong length produces different
     * bytes rather than a different return code.
     */
    {
        unsigned char salt8[] = { 's', 'a', 'l', 't', '0', '1', '2', '3' };
        unsigned char data[] = "the probe's own input";
        const int datalen = (int) sizeof data - 1;
        unsigned char key[32], iv[32];
        int n;

        memset(key, 0xAA, sizeof key);
        memset(iv, 0xAA, sizeof iv);
        n = EVP_BytesToKey(cipher8, md_leg, salt8, NULL, 0, 1, key, iv);
        printf("btk.nodata=%d err=", n);
        drain();
        say_hex("btk.nodata.key", key, 8);
        say_hex("btk.nodata.iv", iv, 8);

        memset(key, 0xAA, sizeof key);
        memset(iv, 0xAA, sizeof iv);
        n = EVP_BytesToKey(cipher8, md_leg, salt8, data, datalen, 1, key, iv);
        printf("btk.count1=%d err=", n);
        drain();
        say_hex("btk.count1.key", key, 8);
        say_hex("btk.count1.iv", iv, 8);

        memset(key, 0xAA, sizeof key);
        memset(iv, 0xAA, sizeof iv);
        n = EVP_BytesToKey(cipher8, md_leg, salt8, data, datalen, 2, key, iv);
        printf("btk.count2=%d err=", n);
        drain();
        say_hex("btk.count2.key", key, 8);
        say_hex("btk.count2.iv", iv, 8);

        /* `count == 0` casts to zero, so the extra loop runs zero times and this equals `count1`. */
        memset(key, 0xAA, sizeof key);
        memset(iv, 0xAA, sizeof iv);
        n = EVP_BytesToKey(cipher8, md_leg, salt8, data, datalen, 0, key, iv);
        printf("btk.count0=%d err=", n);
        drain();
        say_hex("btk.count0.key", key, 8);
        say_hex("btk.count0.iv", iv, 8);

        memset(key, 0xAA, sizeof key);
        memset(iv, 0xAA, sizeof iv);
        n = EVP_BytesToKey(cipher8, md_leg, NULL, data, datalen, 1, key, iv);
        printf("btk.nosalt=%d err=", n);
        drain();
        say_hex("btk.nosalt.key", key, 8);
        say_hex("btk.nosalt.iv", iv, 8);

        /* The 24-byte-key cipher: `24 + 8` exceeds one twenty-byte block, so the outer loop turns
         * a second time and the second block's bytes land in both the key and the IV. */
        memset(key, 0xAA, sizeof key);
        memset(iv, 0xAA, sizeof iv);
        n = EVP_BytesToKey(cipher24, md_leg, salt8, data, datalen, 1, key, iv);
        printf("btk.tworounds=%d err=", n);
        drain();
        say_hex("btk.tworounds.key", key, 24);
        say_hex("btk.tworounds.iv", iv, 8);

        /* Both output pointers NULL: the key is still derived and the length still answered. */
        n = EVP_BytesToKey(cipher8, md_leg, salt8, data, datalen, 1, NULL, NULL);
        printf("btk.noout=%d err=", n);
        drain();
        n = EVP_BytesToKey(cipher8, md_leg, NULL, NULL, 0, 1, NULL, NULL);
        printf("btk.nodata_noout=%d err=", n);
        drain();
    }

    /*
     * ---- the boundaries, named rather than driven -------------------------------------------
     */
    printf("pkcs12.keygen=NOT_MEASURED_REGISTERED_DIVERGENCE\n");
    printf("pbe.cipherinit.pkcs12=NOT_MEASURED_REGISTERED_DIVERGENCE\n");
    printf("v2.kdf_without_keygen_ex=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("v2.pbkdf2.direct=NOT_MEASURED_SYMBOL_IS_LOCAL_IN_THE_AUTHORITY\n");
    printf("v2.pbkdf2.keylen_over_64=NOT_MEASURED_AUTHORITY_ABORTS\n");
    printf("scrypt.keylen_over_64=NOT_MEASURED_AUTHORITY_OVERFLOWS\n");
    printf("scrypt.illegal_params=NOT_MEASURED_PROBE_PROVIDER_ACCEPTS_ANY\n");
    printf("pbe.cipher_nid.legacy=NOT_COMPARED_REGISTERED_DIVERGENCE_D_EVP_CIPHER_LEGACY_NID_1\n");
    printf("btk.overlong_key=NOT_MEASURED_AUTHORITY_ABORTS_evp_key_c_92\n");
    printf("btk.negative_count=NOT_MEASURED_AUTHORITY_LOOPS_2_32_TIMES\n");

    ASN1_TYPE_free(pbeparam);
    ASN1_TYPE_free(wrong_type);
    ASN1_TYPE_free(pbe2_param);
    ASN1_TYPE_free(scrypt_param);
    ASN1_TYPE_free(scrypt_param_kl);
    EVP_MD_free(md_sha1);
    EVP_MD_free(md_md2);
    EVP_MD_free(md_leg);
    EVP_CIPHER_free(cipher8);
    EVP_CIPHER_free(cipher24);
    OSSL_LIB_CTX_set0_default(gprev);
    OSSL_PROVIDER_unload(gprov);
    OSSL_LIB_CTX_free(gctx);
    printf("teardown=1 err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    return 0;
}
