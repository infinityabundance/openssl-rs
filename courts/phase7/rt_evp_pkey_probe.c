/*
 * RT-EVP-PKEY -- `crypto/evp/signature.c`'s entry-point half and `p_lib.c`'s provider half,
 * differentially.
 *
 * The method object's structural check was courted by `RT-EVP-KEYMGMT`'s sibling rules and is not
 * this court's subject. What is here is `evp_pkey_signature_init` and the eighteen exports over it,
 * and the one thing that makes them measurable from outside the library: **a provider whose every
 * callback is a counter**, so a transcription that filled the wrong dispatch field, called the
 * wrong callback for an operation, or forgot a step in the two-iteration fetch is visible as a
 * counter vector rather than as a plausible return code.
 *
 * What is observable, and what makes each arm worth a transcript
 * -------------------------------------------------------------
 *   1. **The dispatch ids 26..32 are not in the struct's order.** `query_key_types` is 26 and the
 *      two message triplets are 27..32, while their struct fields sit between `sign` and
 *      `verify_init`. Every arm below is published with the *header's* `OSSL_FUNC_SIGNATURE_*`
 *      constants, so a transcription that grouped the ids positionally would fill, say,
 *      `verify_message_init` where the probe expects `sign_message_init` -- and the counter vector
 *      after `EVP_PKEY_sign_message_init` would show it.
 *   2. **`legacy:` does not reset `ctx->operation`.** A signature that cannot be produced leaves the
 *      context *armed* with no algorithm context, and the three one-shot entry points have an arm
 *      for exactly that state. `legacy.armed_then_sign` and its two siblings are the only way to
 *      reach those arms from this crate, and they are observations of the label as much as of the
 *      entry point.
 *   3. **The key-type check exists only in the pre-fetched branch.** `EVP_PKEY_sign_init_ex2` and
 *      its siblings hand the init a method, and *that* is where `query_key_types` is called and
 *      where the two name fallbacks live. The plain spellings fetch the method from the key's own
 *      preferred name and never check it at all. `qkt.*`, `fallback.*` and the arms under `full.*`
 *      are the two sides of that.
 *   4. **`$callback == NULL` is `-2` and names the clause**, and the message carries the method's
 *      *type name* and its *description*, so `drain()` below prints a string the probe itself
 *      supplied. One arm per missing callback, and one for each of the two operation callbacks a
 *      message-only method leaves absent.
 *   5. **The property query reaches `newctx`.** `evp_pkey_signature_init` passes `ctx->propquery`
 *      as the method's second `newctx` argument, so the counter says whether it was NULL.
 *   6. **`EVP_PKEY_fromdata` is how a probe gets a key with key data**, and the keymgmt's own
 *      counters say so: `import`, `new`, and -- only at teardown -- the *key data* destructor,
 *      which `EVP_KEYMGMT_free` never calls.
 *
 * Deliberately not observed
 * -------------------------
 *   * **`EVP_PKEY_verify_recover`'s `verify_recover == NULL` arm** is unreachable through this
 *     unit's exports, and that is a fact about the structural check rather than about the call: an
 *     armed `EVP_PKEY_OP_VERIFYRECOVER` operation requires `verify_recover_init` to be present, and
 *     `evp_signature_from_algorithm` refuses a method that publishes an init without its operation
 *     callback. The arm is written in the candidate for the same reason the authority has it.
 *   * **the four stream entry points on a context left armed by a `legacy:` refusal.** They read
 *     `ctx->op.sig.signature` with no test, and that pointer is NULL there, so the authority
 *     dereferences it. The four sites are printed as a boundary rather than called. The fault was
 *     measured: four programs, each against the pinned authority and against the candidate shell,
 *     each printing its markers line-buffered and then dying with **exit 139** -- the same four, the
 *     same way, on both sides. Two sides faulting identically is not agreement and not a
 *     divergence, so nothing is registered in `docs/SECURITY_DIVERGENCE_POLICY.md` and
 *     `docs/DECISIONS.md` D189 records the measurement instead.
 *   * **`evp_pkey_ctx_is_legacy`'s entry to `legacy:`.** It is `ctx->keymgmt == NULL`, and this
 *     crate cannot build such a context: `int_ctx_new` always fetches a method and refuses
 *     otherwise. The authority reaches it only through the legacy-typed constructors.
 *   * **the `ctx == NULL` arm of all ten `m_sigver.c` exports.** There is no such arm: the file has
 *     no NULL test on `ctx`, so `do_sigver_init`'s first statement (`m_sigver.c:53`,
 *     `evp_md_ctx_free_algctx(ctx)`) and the six operate entry points' `ctx->pctx` read (`:407`,
 *     `:457`, `:506`, `:676`) dereference it. The boundary is printed as one line rather than
 *     called; a probe that called it would abort the harness on **both** sides, which is not
 *     agreement.
 *   * **`EVP_PKEY_digestsign_supports_digest`'s `-1`.** It is the `EVP_MD_CTX_new` failure and an
 *     allocation has no injectable seam here; faking one would measure the seam. Named, not
 *     driven (`p_lib.c:1404`).
 *   * **`do_sigver_init`'s `ERR_R_INTERNAL_ERROR` assert (`m_sigver.c:105`), the NULL
 *     `query_operation_name` (`:112`) and the legacy `NO_DEFAULT_DIGEST` (`:318`).** The first two
 *     need a key whose `keymgmt` disagrees with its context's, which `int_ctx_new` cannot build;
 *     the third sits below the label's unconditional `pmeth == NULL` refusal.
 *
 * The 7.4e half -- `p_lib.c`'s provider half, the five `EVP_PKEY_CTX_*` accessors beside it, and
 * the four `EVP_PKEY_new_raw_*` constructors -- has its own comment at the head of its provider
 * block below. Note that `EVP_PKEY_CTX_set_signature` used to be on the list above; 7.4e landed it
 * and the arms under `ctxsig.*` drive it, so the bullet is gone rather than left stale.
 *
 * Addresses are never printed. Every observation is a relation between two pointers this probe
 * holds, a presence answer, a return code, a counter vector, a bounded byte comparison or a
 * `strcmp` against the probe's own input.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

/* ------------------------------------------------------------------ transcript helpers */

/*
 * Every error on the queue, oldest first, as `reason[data]@func/line`. The **file is deliberately
 * not printed**: it embeds the build prefix. The line and the function are printed and do not:
 * they are the authority's own coordinates, which is what `raise_site` records them for, and two
 * sides that raise from different statements in the same function would otherwise be
 * indistinguishable.
 */
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

static void sayr(const char *key, int r)
{
    printf("%s=%d err=", key, r);
    drain();
}

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=", key, v);
    drain();
}

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=", key, p == NULL ? "NULL" : "nonnull");
    drain();
}

/* ------------------------------------------------------------------ the counters
 *
 * One per signature callback, plus three shape counters that record *how* a callback was called
 * rather than how often: whether the caller's output buffer was absent, whether the length it
 * handed over was the zero the entry points pass for an absent buffer, and whether a params array
 * reached an init at all. A wrong dispatch field shows up as a wrong counter; a wrong argument
 * convention shows up as a wrong shape.
 */

static int n_newctx, n_newctx_no_propq, n_freectx, n_dupctx;
static int n_sign_init, n_sign, n_sign_null_out, n_sign_zero_len;
static int n_smi, n_smu, n_smf, n_smf_zero_len;
static int n_vi, n_verify;
static int n_vmi, n_vmu, n_vmf;
static int n_vri, n_vr, n_vr_zero_len;
static int n_qkt, n_init_params;
/* The keymgmt's own, so the key's path is visible beside the method's. `n_km_free` is the *key
 * data* destructor: `EVP_KEYMGMT_free` must never reach it. */
static int n_km_new, n_km_free, n_km_has, n_km_get, n_km_import, n_km_qon;

static void reset_c(void)
{
    n_newctx = n_newctx_no_propq = n_freectx = n_dupctx = 0;
    n_sign_init = n_sign = n_sign_null_out = n_sign_zero_len = 0;
    n_smi = n_smu = n_smf = n_smf_zero_len = 0;
    n_vi = n_verify = 0;
    n_vmi = n_vmu = n_vmf = 0;
    n_vri = n_vr = n_vr_zero_len = 0;
    n_qkt = n_init_params = 0;
    n_km_new = n_km_free = n_km_has = n_km_get = n_km_import = n_km_qon = 0;
    ERR_clear_error();
}

static void say_c(const char *key)
{
    printf("%s=newctx:%d,no_propq:%d,free:%d,dup:%d,"
           "sign_init:%d,sign:%d,sign_null_out:%d,sign_zero_len:%d,"
           "smi:%d,smu:%d,smf:%d,smf_zero_len:%d,"
           "vi:%d,v:%d,vmi:%d,vmu:%d,vmf:%d,vri:%d,vr:%d,vr_zero_len:%d,"
           "qkt:%d,init_params:%d\n",
           key, n_newctx, n_newctx_no_propq, n_freectx, n_dupctx,
           n_sign_init, n_sign, n_sign_null_out, n_sign_zero_len,
           n_smi, n_smu, n_smf, n_smf_zero_len,
           n_vi, n_verify, n_vmi, n_vmu, n_vmf, n_vri, n_vr, n_vr_zero_len,
           n_qkt, n_init_params);
    ERR_clear_error();
}

static void say_k(const char *key)
{
    printf("%s=new:%d,free:%d,has:%d,get_params:%d,import:%d,qon:%d\n",
           key, n_km_new, n_km_free, n_km_has, n_km_get, n_km_import, n_km_qon);
    ERR_clear_error();
}

/*
 * 7.4f. One counter per "digest" signature callback, plus the two shape questions the entry
 * points' argument conventions turn on: whether the init was handed a digest **name** (and whether
 * it was the one the caller passed) and whether an absent output buffer reached the provider as a
 * length query. The four init counters are separate because `do_sigver_init` reaches
 * `digest_sign_init` and `digest_verify_init` down the same code and a transcription that swapped
 * them would leave a
 * counter at zero rather than failing.
 */
static int n_dsi, n_dsi_named, n_dsi_sha256, n_dsi_nomd, n_dsi_params;
static int n_dsu, n_dsf, n_dsf_query, n_dsf_short;
static int n_ds, n_ds_null_out, n_ds_short;
static int n_dvi, n_dvi_named, n_dvi_sha256, n_dvi_nomd;
static int n_dvu, n_dvf, n_dvf_short, n_dv, n_dv_short;

/* `g_dsg_init_fails` makes the two digest `*_init` callbacks answer 0, which is the only way the
 * `NO_DEFAULT_DIGEST`/`PROVIDER_SIGNATURE_FAILURE` pair is reachable with an init that was
 * *found*. `g_dsg_newctx_null` makes the method's `newctx` answer NULL, for the arm that refuses
 * an algorithm context. */
static int g_dsg_init_fails;

static void reset_dsg(void)
{
    n_dsi = n_dsi_named = n_dsi_sha256 = n_dsi_nomd = n_dsi_params = 0;
    n_dsu = n_dsf = n_dsf_query = n_dsf_short = 0;
    n_ds = n_ds_null_out = n_ds_short = 0;
    n_dvi = n_dvi_named = n_dvi_sha256 = n_dvi_nomd = 0;
    n_dvu = n_dvf = n_dvf_short = n_dv = n_dv_short = 0;
    ERR_clear_error();
}

static void say_dsg(const char *key)
{
    printf("%s=dsi:%d,dsi_named:%d,dsi_sha256:%d,dsi_nomd:%d,dsi_params:%d,"
           "dsu:%d,dsf:%d,dsf_query:%d,dsf_short:%d,"
           "ds:%d,ds_null_out:%d,ds_short:%d,"
           "dvi:%d,dvi_named:%d,dvi_sha256:%d,dvi_nomd:%d,"
           "dvu:%d,dvf:%d,dvf_short:%d,dv:%d,dv_short:%d\n",
           key, n_dsi, n_dsi_named, n_dsi_sha256, n_dsi_nomd, n_dsi_params,
           n_dsu, n_dsf, n_dsf_query, n_dsf_short,
           n_ds, n_ds_null_out, n_ds_short,
           n_dvi, n_dvi_named, n_dvi_sha256, n_dvi_nomd,
           n_dvu, n_dvf, n_dvf_short, n_dv, n_dv_short);
    ERR_clear_error();
}

/* The counters and the two out-relations are the whole transcript for this half; no address is
 * printed. `sha256` above is the string comparison the init's `mdname` argument is measured with. */
static int dsg_dsig_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    (void) ctx;
    (void) provkey;
    n_dsi++;
    if (mdname == NULL) {
        n_dsi_nomd++;
    } else {
        n_dsi_named++;
        if (strcmp(mdname, "SHA256") == 0)
            n_dsi_sha256++;
    }
    if (params != NULL)
        n_dsi_params++;
    return g_dsg_init_fails ? 0 : 1;
}

static int dsg_dsig_update(void *ctx, const unsigned char *in, size_t inl)
{
    (void) ctx;
    (void) in;
    (void) inl;
    n_dsu++;
    return 1;
}

/* The two-call convention lives here: a NULL buffer is the length query and answers 8; a buffer
 * smaller than 8 is the refusal, which is what the entry point turns into
 * `PROVIDER_SIGNATURE_FAILURE`. */
static int dsg_dsig_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    (void) ctx;
    n_dsf++;
    if (sig == NULL) {
        n_dsf_query++;
        if (siglen != NULL)
            *siglen = 8;
        return 1;
    }
    if (sigsize < 8) {
        n_dsf_short++;
        return 0;
    }
    if (siglen != NULL)
        *siglen = 8;
    return 1;
}

static int dsg_dsig_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                         const unsigned char *tbs, size_t tbslen)
{
    (void) ctx;
    (void) tbs;
    (void) tbslen;
    n_ds++;
    if (sig == NULL) {
        n_ds_null_out++;
        if (siglen != NULL)
            *siglen = 8;
        return 1;
    }
    if (sigsize < 8) {
        n_ds_short++;
        return 0;
    }
    if (siglen != NULL)
        *siglen = 8;
    return 1;
}

static int dsg_dvi_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    (void) ctx;
    (void) provkey;
    (void) params;
    n_dvi++;
    if (mdname == NULL) {
        n_dvi_nomd++;
    } else {
        n_dvi_named++;
        if (strcmp(mdname, "SHA256") == 0)
            n_dvi_sha256++;
    }
    return 1;
}

static int dsg_dvu(void *ctx, const unsigned char *in, size_t inl)
{
    (void) ctx;
    (void) in;
    (void) inl;
    n_dvu++;
    return 1;
}

/* A verify final has no buffer convention; the "too small" arm is a signature whose length is not
 * the provider's eight. */
static int dsg_dvf(void *ctx, const unsigned char *sig, size_t siglen)
{
    (void) ctx;
    (void) sig;
    n_dvf++;
    if (siglen != 8) {
        n_dvf_short++;
        return 0;
    }
    return 1;
}

static int dsg_dv(void *ctx, const unsigned char *sig, size_t siglen,
                  const unsigned char *tbs, size_t tbslen)
{
    (void) ctx;
    (void) sig;
    (void) tbs;
    (void) tbslen;
    n_dv++;
    if (siglen != 8) {
        n_dv_short++;
        return 0;
    }
    return 1;
}

/* One signature method whose `newctx` refuses, so the `algctx == NULL` arm of `do_sigver_init`
 * (m_sigver.c:201) has a method to refuse it. */
static void *dsg_newctx_null(void *provctx, const char *propq)
{
    (void) provctx;
    (void) propq;
    return NULL;
}

/* The md-level parameter pair, published only so `EVP_MD_CTX_set_params`'s pctx-first block has a
 * signature method to find. The counter says whether the redirect happened rather than the digest
 * path. */
static int n_setmd, n_getmd;

static int dsg_set_md_params(void *ctx, const OSSL_PARAM params[])
{
    (void) ctx;
    (void) params;
    n_setmd++;
    return 1;
}

static int dsg_get_md_params(void *ctx, OSSL_PARAM params[])
{
    (void) ctx;
    (void) params;
    n_getmd++;
    return 1;
}

static const OSSL_PARAM *dsg_gettable_md_params(void *ctx)
{
    static const OSSL_PARAM md_tab[] = {
        OSSL_PARAM_size_t("court-md-param", NULL),
        OSSL_PARAM_END
    };

    (void) ctx;
    return md_tab;
}

static const OSSL_PARAM *dsg_settable_md_params(void *ctx)
{
    (void) ctx;
    return dsg_gettable_md_params(NULL);
}

/* `g_fail_ops` makes the four *operation* callbacks answer 0, so the entry points' FAILURE arm is
 * reachable without a second dispatch table. `g_qon` is the name the keymgmt answers for
 * `OSSL_OP_SIGNATURE`, and it is the probe's, not the library's: it is how each pre-fetched arm is
 * made to pass the key-type check through fallback 2. */
static int g_fail_ops;
static const char *g_qon = "COURT-SIG";

/* The three arrays `SIG-Qkt` can answer. The empty one is a refusal rather than a vacuous success,
 * and the non-matching one takes the *same* path as the empty one -- the walk's terminator is what
 * reports both. */
static const char *kt_match[] = { "COURT-SIGKEY", NULL };
static const char *kt_nomatch[] = { "COURT-NOT-A-KEY-TYPE", NULL };
static const char *kt_empty[] = { NULL };
static const char **g_keytypes;

/* ------------------------------------------------------------------ the signature callbacks */

static void *sig_newctx(void *provctx, const char *propq)
{
    (void) provctx;
    n_newctx++;
    if (propq == NULL)
        n_newctx_no_propq++;
    return malloc(1);
}

static void sig_freectx(void *ctx)
{
    n_freectx++;
    free(ctx);
}

static void *sig_dupctx(void *ctx)
{
    n_dupctx++;
    if (ctx == NULL)
        return NULL;
    return malloc(1);
}

static int sig_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    (void) ctx;
    (void) provkey;
    n_sign_init++;
    if (params != NULL)
        n_init_params++;
    return 1;
}

static int sig_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                    const unsigned char *tbs, size_t tbslen)
{
    (void) ctx;
    (void) tbs;
    (void) tbslen;
    n_sign++;
    if (sig == NULL)
        n_sign_null_out++;
    if (sigsize == 0)
        n_sign_zero_len++;
    if (siglen != NULL)
        *siglen = 8;
    return g_fail_ops ? 0 : 1;
}

static int sig_smi(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    (void) ctx;
    (void) provkey;
    n_smi++;
    if (params != NULL)
        n_init_params++;
    return 1;
}

static int sig_smu(void *ctx, const unsigned char *in, size_t inlen)
{
    (void) ctx;
    (void) in;
    (void) inlen;
    n_smu++;
    return 1;
}

static int sig_smf(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    (void) ctx;
    n_smf++;
    if (sigsize == 0)
        n_smf_zero_len++;
    if (siglen != NULL)
        *siglen = 8;
    return g_fail_ops ? 0 : 1;
}

static int sig_vi(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    (void) ctx;
    (void) provkey;
    n_vi++;
    if (params != NULL)
        n_init_params++;
    return 1;
}

static int sig_verify(void *ctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    (void) ctx;
    (void) sig;
    (void) siglen;
    (void) tbs;
    (void) tbslen;
    n_verify++;
    return g_fail_ops ? 0 : 1;
}

static int sig_vmi(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    (void) ctx;
    (void) provkey;
    n_vmi++;
    if (params != NULL)
        n_init_params++;
    return 1;
}

static int sig_vmu(void *ctx, const unsigned char *in, size_t inlen)
{
    (void) ctx;
    (void) in;
    (void) inlen;
    n_vmu++;
    return 1;
}

static int sig_vmf(void *ctx)
{
    (void) ctx;
    n_vmf++;
    return g_fail_ops ? 0 : 1;
}

static int sig_vri(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    (void) ctx;
    (void) provkey;
    n_vri++;
    if (params != NULL)
        n_init_params++;
    return 1;
}

static int sig_vr(void *ctx, unsigned char *rout, size_t *routlen, size_t routsize,
                  const unsigned char *sig, size_t siglen)
{
    (void) ctx;
    (void) sig;
    (void) siglen;
    n_vr++;
    if (routsize == 0)
        n_vr_zero_len++;
    if (routlen != NULL)
        *routlen = 8;
    return g_fail_ops ? 0 : 1;
}

static const char **sig_query_key_types(void)
{
    n_qkt++;
    return g_keytypes;
}

/* ------------------------------------------------------------------ the keymgmt callbacks */

static void *km_new(void *provctx)
{
    (void) provctx;
    n_km_new++;
    return malloc(1);
}

static void km_free(void *keydata)
{
    n_km_free++;
    free(keydata);
}

static int km_has(const void *keydata, int selection)
{
    (void) keydata;
    (void) selection;
    n_km_has++;
    return 1;
}

static int km_get_params(void *keydata, OSSL_PARAM params[])
{
    (void) keydata;
    (void) params;
    n_km_get++;
    return 1;
}

static int km_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    (void) keydata;
    (void) selection;
    (void) params;
    n_km_import++;
    return 1;
}

static const OSSL_PARAM km_gettable[] = {
    OSSL_PARAM_utf8_string("court-gettable", NULL, 0),
    OSSL_PARAM_END
};

/* Published only so the `get_params`/`gettable_params` pair is complete: the structural check
 * counts *pairs* and refuses a lone `get_params`. Nothing in this unit's path asks for the table. */
static const OSSL_PARAM *km_gettable_params(void)
{
    return km_gettable;
}

static const OSSL_PARAM *km_import_types(int selection)
{
    (void) selection;
    return NULL;
}

static const char *km_qon(int operation_id)
{
    n_km_qon++;
    if (operation_id == OSSL_OP_SIGNATURE)
        return g_qon;
    return NULL;
}

/* ------------------------------------------------------------------ the dispatch tables
 *
 * Eight tables, one per *shape* the structural check admits, and the arms below pick the shape the
 * entry point under test is supposed to refuse. Each table is a compile-time constant with the
 * header's ids, so the walk in the candidate and the walk in the authority fill the same fields.
 */

static const OSSL_DISPATCH sig_full_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) sig_sign },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, (void (*)(void)) sig_smi },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, (void (*)(void)) sig_smu },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, (void (*)(void)) sig_smf },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void)) sig_vi },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) sig_verify },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, (void (*)(void)) sig_vmi },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, (void (*)(void)) sig_vmu },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, (void (*)(void)) sig_vmf },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, (void (*)(void)) sig_vri },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, (void (*)(void)) sig_vr },
    { 0, NULL }
};

/* The full set plus the one callback that is only reachable through the pre-fetched branch. */
static const OSSL_DISPATCH sig_qkt_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void)) sig_vi },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) sig_verify },
    { OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES, (void (*)(void)) sig_query_key_types },
    { 0, NULL }
};

static const OSSL_DISPATCH sig_sign_only_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) sig_sign },
    { 0, NULL }
};

static const OSSL_DISPATCH sig_verify_only_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void)) sig_vi },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) sig_verify },
    { 0, NULL }
};

static const OSSL_DISPATCH sig_msgsign_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, (void (*)(void)) sig_smi },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, (void (*)(void)) sig_smu },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, (void (*)(void)) sig_smf },
    { 0, NULL }
};

static const OSSL_DISPATCH sig_msgverify_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, (void (*)(void)) sig_vmi },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, (void (*)(void)) sig_vmu },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, (void (*)(void)) sig_vmf },
    { 0, NULL }
};

/* `sign_message_init` with a `sign` and neither of the stream pair. The check admits it -- the
 * XOR clause is "update without final", and neither is present -- which is what makes the two
 * `sign_message_*` NULL arms reachable. */
static const OSSL_DISPATCH sig_signmsghalf_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, (void (*)(void)) sig_smi },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) sig_sign },
    { 0, NULL }
};

static const OSSL_DISPATCH sig_verifymsghalf_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, (void (*)(void)) sig_vmi },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) sig_verify },
    { 0, NULL }
};

/*
 * The `DSG-*` tables, one per shape the digest-signature structural check admits. The check is
 * *different* from the nine above: a digest method needs `newctx`+`freectx`, at least one init,
 * and for each init either its one-shot operation or **both** of the update/final pair. So:
 *
 *   `DSG-FULL`       every digest callback, so every arm the entry points have is reachable.
 *   `DSG-NOSTREAM`   a one-shot only: `digest_sign_update`/`_final` are absent, which is the
 *                    `PROVIDER_SIGNATURE_NOT_SUPPORTED` pair of `EVP_DigestSignUpdate`/`Final`.
 *   `DSG-SIGNONLY`   a signer with no `digest_verify_init`, which is how a `VERIFYCTX` operation
 *                    reaches `m_sigver.c:258`.
 *   `DSG-VERIFYONLY` the mirror, for `m_sigver.c:266`.
 *   `DSG-NONEWCTX`   `newctx` answers NULL, for `m_sigver.c:201`.
 *   `DSG-NODUP`      no `dupctx`, so `EVP_PKEY_CTX_dup` fails and the final marks the context.
 *   `DSG-SETMD`      the md-parameter pair, for the `EVP_MD_CTX_set_params` redirect.
 */
static const OSSL_DISPATCH dsg_full_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) dsg_dsig_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void)) dsg_dsig_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void)) dsg_dsig_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void)) dsg_dsig_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) dsg_dvi_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void)) dsg_dvu },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void)) dsg_dvf },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void)) dsg_dv },
    { 0, NULL }
};

static const OSSL_DISPATCH dsg_nostream_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) dsg_dsig_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void)) dsg_dsig_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) dsg_dvi_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void)) dsg_dv },
    { 0, NULL }
};

static const OSSL_DISPATCH dsg_signonly_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) dsg_dsig_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void)) dsg_dsig_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void)) dsg_dsig_final },
    { 0, NULL }
};

static const OSSL_DISPATCH dsg_verifyonly_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) dsg_dvi_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void)) dsg_dvu },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void)) dsg_dvf },
    { 0, NULL }
};

static const OSSL_DISPATCH dsg_nonewctx_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) dsg_newctx_null },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) dsg_dsig_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void)) dsg_dsig_sign },
    { 0, NULL }
};

static const OSSL_DISPATCH dsg_nodup_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) dsg_dsig_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void)) dsg_dsig_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void)) dsg_dsig_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) dsg_dvi_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void)) dsg_dvu },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void)) dsg_dvf },
    { 0, NULL }
};

static const OSSL_DISPATCH dsg_setmd_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) dsg_dsig_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void)) dsg_dsig_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void)) dsg_dsig_final },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void)) dsg_set_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void)) dsg_settable_md_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void)) dsg_get_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void)) dsg_gettable_md_params },
    { 0, NULL }
};

static const OSSL_DISPATCH kmgm_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) km_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) km_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) km_gettable_params },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) km_import_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void)) km_qon },
    { 0, NULL }
};

/* ==================================================================== 7.4e: the provider */
/*
 * The 7.4e surface is about *parameters*: the four cache properties, the group name, the encoded
 * public key, the raw key pair, the default digest and the generation parameter walk. So the
 * provider gains three things beside `COURT-SIGKEY`, and each exists for the arms below rather
 * than for symmetry:
 *
 *   `COURT-PKEY`     a key type that publishes every one of those parameters. Each answer is a
 *                    *global*, so "the provider does not answer" is one assignment away rather
 *                    than a second key type -- which is what makes the refusal arms reachable.
 *   `EC`/`RSA`/       three generation-only key types. `EC` and `RSA` are the two names
 *   `COURT-GEN`      `EVP_PKEY_Q_keygen`'s `va_arg` walk reads an argument for, and the third is
 *                    the control: a name it reads **nothing** for.
 *   `SHA256`         a digest, so `legacy_asn1_ctrl_to_param`'s fetch-namemap-NID path has
 *                    something to find. Only its *name* matters; no callback is ever called.
 *
 * `SIG-SetParams` is the fourth and the smallest: a signature method with a `set_ctx_params`, so
 * `EVP_PKEY_CTX_set_signature`'s parameter is observable at the provider instead of vanishing.
 */

static int pn_new_calls, pn_free_calls, pn_get_calls, pn_set_calls, pn_import_calls;
static int pn_export_calls, pn_has_calls, pn_match_calls, pn_qon_calls;
static int g_pn_get_fails;      /* answer 0 from `get_params` */
static int g_pn_get_silent;     /* answer 1 from `get_params` without filling anything */
static int g_pn_has_data = 1;   /* `has(DOMAIN_PARAMETERS)` for a key **with** key data */
static int g_pn_has_empty;      /* ... and for a typed key with none */
static int g_pn_match = 1;      /* what `match` answers */
static int g_pn_no_encpub;      /* do not publish `encoded-pub-key` at all */
static int g_pn_import_fails;   /* `import` answers 0, so `fromdata` refuses */
static const char *g_pn_group;
static const char *g_pn_default_digest;
static const char *g_pn_mandatory_digest;
static const char *g_pn_qon = "COURT-SIG";
static unsigned char g_pn_encpub[16];
static size_t g_pn_encpub_len;
static unsigned char g_pn_priv[16], g_pn_pub[16];
static size_t g_pn_priv_len, g_pn_pub_len;

static void reset_pn(void)
{
    pn_new_calls = pn_free_calls = pn_get_calls = pn_set_calls = pn_import_calls = 0;
    pn_export_calls = pn_has_calls = pn_match_calls = pn_qon_calls = 0;
    ERR_clear_error();
}

static void say_pn(const char *key)
{
    printf("%s=new:%d,free:%d,get:%d,set:%d,import:%d,export:%d,has:%d,match:%d,qon:%d\n",
           key, pn_new_calls, pn_free_calls, pn_get_calls, pn_set_calls, pn_import_calls,
           pn_export_calls, pn_has_calls, pn_match_calls, pn_qon_calls);
    ERR_clear_error();
}

static void *pn_new(void *provctx)
{
    (void) provctx;
    pn_new_calls++;
    return malloc(1);
}

static void pn_free(void *keydata)
{
    pn_free_calls++;
    free(keydata);
}

static int pn_has(const void *keydata, int selection)
{
    pn_has_calls++;
    if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
        return keydata != NULL ? g_pn_has_data : g_pn_has_empty;
    return 1;
}

static int pn_match(const void *keydata1, const void *keydata2, int selection)
{
    (void) keydata1;
    (void) keydata2;
    (void) selection;
    pn_match_calls++;
    return g_pn_match;
}

static const char *pn_qon(int operation_id)
{
    (void) operation_id;
    pn_qon_calls++;
    return g_pn_qon;
}

static int pn_get_params(void *keydata, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void) keydata;
    pn_get_calls++;
    if (g_pn_get_fails)
        return 0;
    if (g_pn_get_silent)
        return 1;

    p = OSSL_PARAM_locate(params, "bits");
    if (p != NULL)
        OSSL_PARAM_set_int(p, 1234);
    p = OSSL_PARAM_locate(params, "security-bits");
    if (p != NULL)
        OSSL_PARAM_set_int(p, 99);
    p = OSSL_PARAM_locate(params, "security-category");
    if (p != NULL)
        OSSL_PARAM_set_int(p, 3);
    p = OSSL_PARAM_locate(params, "max-size");
    if (p != NULL)
        OSSL_PARAM_set_int(p, 7);
    p = OSSL_PARAM_locate(params, "group");
    if (p != NULL && g_pn_group != NULL)
        OSSL_PARAM_set_utf8_string(p, g_pn_group);
    p = OSSL_PARAM_locate(params, "default-digest");
    if (p != NULL && g_pn_default_digest != NULL)
        OSSL_PARAM_set_utf8_string(p, g_pn_default_digest);
    p = OSSL_PARAM_locate(params, "mandatory-digest");
    if (p != NULL && g_pn_mandatory_digest != NULL)
        OSSL_PARAM_set_utf8_string(p, g_pn_mandatory_digest);
    p = OSSL_PARAM_locate(params, "encoded-pub-key");
    if (p != NULL && !g_pn_no_encpub)
        OSSL_PARAM_set_octet_string(p, g_pn_encpub, g_pn_encpub_len);
    return 1;
}

static int pn_set_params(void *keydata, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const void *data = NULL;
    size_t len = 0;

    (void) keydata;
    pn_set_calls++;
    p = OSSL_PARAM_locate_const(params, "encoded-pub-key");
    if (p != NULL && OSSL_PARAM_get_octet_string_ptr(p, &data, &len) && data != NULL) {
        if (len > sizeof g_pn_encpub)
            len = sizeof g_pn_encpub;
        memcpy(g_pn_encpub, data, len);
        g_pn_encpub_len = len;
    }
    return 1;
}

static int pn_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const void *data = NULL;
    size_t len = 0;

    (void) keydata;
    (void) selection;
    pn_import_calls++;
    if (g_pn_import_fails)
        return 0;
    p = OSSL_PARAM_locate_const(params, "priv");
    if (p != NULL && OSSL_PARAM_get_octet_string_ptr(p, &data, &len) && data != NULL) {
        if (len > sizeof g_pn_priv)
            len = sizeof g_pn_priv;
        memcpy(g_pn_priv, data, len);
        g_pn_priv_len = len;
    }
    p = OSSL_PARAM_locate_const(params, "pub");
    if (p != NULL && OSSL_PARAM_get_octet_string_ptr(p, &data, &len) && data != NULL) {
        if (len > sizeof g_pn_pub)
            len = sizeof g_pn_pub;
        memcpy(g_pn_pub, data, len);
        g_pn_pub_len = len;
    }
    return 1;
}

/*
 * The exporter `EVP_PKEY_get_raw_private_key`/`_public_key` reach through
 * `evp_keymgmt_util_export`, and the reason it publishes **both** halves is that
 * `get_raw_key_details` locates only the one the caller selected: publishing one and not the other
 * would make the other arm a refusal for a reason the probe invented.
 */
static int pn_export(const void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    OSSL_PARAM params[3];

    (void) keydata;
    (void) selection;
    pn_export_calls++;
    params[0] = OSSL_PARAM_construct_octet_string("priv", g_pn_priv, g_pn_priv_len);
    params[1] = OSSL_PARAM_construct_octet_string("pub", g_pn_pub, g_pn_pub_len);
    params[2] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM pn_gettable[] = {
    OSSL_PARAM_int("bits", NULL),
    OSSL_PARAM_int("security-bits", NULL),
    OSSL_PARAM_int("security-category", NULL),
    OSSL_PARAM_int("max-size", NULL),
    OSSL_PARAM_utf8_string("group", NULL, 0),
    OSSL_PARAM_utf8_string("default-digest", NULL, 0),
    OSSL_PARAM_utf8_string("mandatory-digest", NULL, 0),
    OSSL_PARAM_octet_string("encoded-pub-key", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pn_gettable_params(void)
{
    return pn_gettable;
}

static const OSSL_PARAM pn_settable[] = {
    OSSL_PARAM_octet_string("encoded-pub-key", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pn_settable_params(void)
{
    return pn_settable;
}

static const OSSL_PARAM pn_export_tab[] = {
    OSSL_PARAM_octet_string("priv", NULL, 0),
    OSSL_PARAM_octet_string("pub", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pn_export_types(int selection)
{
    (void) selection;
    return pn_export_tab;
}

static const OSSL_PARAM pn_import_tab[] = {
    OSSL_PARAM_octet_string("priv", NULL, 0),
    OSSL_PARAM_octet_string("pub", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pn_import_types(int selection)
{
    (void) selection;
    return pn_import_tab;
}

static const OSSL_DISPATCH pn_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) pn_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) pn_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) pn_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void)) pn_match },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void)) pn_qon },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) pn_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) pn_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void)) pn_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void)) pn_settable_params },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) pn_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) pn_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) pn_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) pn_export_types },
    { 0, NULL }
};

/* ---------------------------------------------------------------- the generation-only key types */

static int gn_init_calls, gn_cleanup_calls, gn_set_calls, gn_get_calls, gn_gen_calls, gn_free_calls;
static int gn_saw_bits, gn_saw_group, gn_saw_nothing, gn_saw_aid;
static size_t g_gen_bits;
static char g_gen_group[64];
static unsigned char g_gen_aid[64];
static size_t g_gen_aid_len;

static void reset_gen(void)
{
    gn_init_calls = gn_cleanup_calls = gn_set_calls = gn_get_calls = gn_gen_calls = 0;
    gn_free_calls = 0;
    gn_saw_bits = gn_saw_group = gn_saw_nothing = gn_saw_aid = 0;
    g_gen_bits = 0;
    g_gen_group[0] = '\0';
    g_gen_aid_len = 0;
    ERR_clear_error();
}

static void say_gen(const char *key)
{
    printf("%s=init:%d,cleanup:%d,set:%d,get:%d,gen:%d,free:%d,"
           "bits:%d,saw_bits:%d,saw_group:%d,saw_nothing:%d,saw_aid:%d\n",
           key, gn_init_calls, gn_cleanup_calls, gn_set_calls, gn_get_calls, gn_gen_calls,
           gn_free_calls, (int) g_gen_bits, gn_saw_bits, gn_saw_group, gn_saw_nothing,
           gn_saw_aid);
    ERR_clear_error();
}

static void *pk_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void) provctx;
    (void) selection;
    (void) params;
    gn_init_calls++;
    return malloc(1);
}

static void pk_gen_cleanup(void *genctx)
{
    gn_cleanup_calls++;
    free(genctx);
}

static int pk_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const void *data = NULL;
    const char *s = NULL;
    size_t len = 0;

    (void) genctx;
    gn_set_calls++;

    /* The control arm: `EVP_PKEY_Q_keygen` read **nothing** for this name, so the first parameter
     * is the array's own terminator. */
    if (params == NULL || params[0].key == NULL) {
        gn_saw_nothing++;
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, "bits");
    if (p != NULL && OSSL_PARAM_get_size_t(p, &g_gen_bits))
        gn_saw_bits++;
    p = OSSL_PARAM_locate_const(params, "group");
    if (p != NULL && OSSL_PARAM_get_utf8_string_ptr(p, &s) && s != NULL) {
        strncpy(g_gen_group, s, sizeof g_gen_group - 1);
        g_gen_group[sizeof g_gen_group - 1] = '\0';
        gn_saw_group++;
    }
    p = OSSL_PARAM_locate_const(params, "algorithm-id-params");
    if (p != NULL && OSSL_PARAM_get_octet_string_ptr(p, &data, &len) && data != NULL) {
        if (len > sizeof g_gen_aid)
            len = sizeof g_gen_aid;
        memcpy(g_gen_aid, data, len);
        g_gen_aid_len = len;
        gn_saw_aid++;
    }
    return 1;
}

static const OSSL_PARAM pk_gen_settable[] = {
    OSSL_PARAM_size_t("bits", NULL),
    OSSL_PARAM_utf8_string("group", NULL, 0),
    OSSL_PARAM_octet_string("algorithm-id-params", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pk_gen_settable_params(void *genctx, void *provctx)
{
    (void) genctx;
    (void) provctx;
    return pk_gen_settable;
}

static void *pk_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    (void) genctx;
    (void) cb;
    (void) cbarg;
    gn_gen_calls++;
    return malloc(1);
}

static int pk_gen_get_params(void *genctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void) genctx;
    gn_get_calls++;
    p = OSSL_PARAM_locate(params, "group");
    if (p != NULL && g_gen_group[0] != '\0')
        OSSL_PARAM_set_utf8_string(p, g_gen_group);
    p = OSSL_PARAM_locate(params, "algorithm-id-params");
    if (p != NULL && g_gen_aid_len != 0)
        OSSL_PARAM_set_octet_string(p, g_gen_aid, g_gen_aid_len);
    return 1;
}

static const OSSL_PARAM pk_gen_gettable[] = {
    OSSL_PARAM_utf8_string("group", NULL, 0),
    OSSL_PARAM_octet_string("algorithm-id-params", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pk_gen_gettable_params(void *genctx, void *provctx)
{
    (void) genctx;
    (void) provctx;
    return pk_gen_gettable;
}

static int pk_gen_free(void *keydata)
{
    gn_free_calls++;
    free(keydata);
    return 1;
}

static int pk_gen_has(const void *keydata, int selection)
{
    (void) keydata;
    (void) selection;
    return 1;
}

static const OSSL_DISPATCH pk_gen_fns[] = {
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) pk_gen_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) pk_gen_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) pk_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) pk_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) pk_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) pk_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void)) pk_gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (void (*)(void)) pk_gen_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) pk_gen },
    { 0, NULL }
};

/* ---------------------------------------------------------------- the digest, and `SIG-SetParams` */

static void *dg_newctx(void *provctx)
{
    (void) provctx;
    return malloc(1);
}

static void dg_freectx(void *vctx)
{
    free(vctx);
}

static int dg_init(void *vctx, const OSSL_PARAM params[])
{
    (void) vctx;
    (void) params;
    return 1;
}

static int dg_update(void *vctx, const unsigned char *in, size_t inl)
{
    (void) vctx;
    (void) in;
    (void) inl;
    return 1;
}

static int dg_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void) vctx;
    (void) out;
    (void) outsz;
    if (outl != NULL)
        *outl = 0;
    return 1;
}

/*
 * Two parameters, and both are load-bearing for a *different* reason than the SHA256 name above:
 * `evp_md_cache_constants` asks for them at fetch time and **fails the fetch** if either is left
 * unanswered. So this callback is what makes `EVP_MD_fetch(ctx, "SHA256", NULL)` a success, which
 * is what `do_sigver_init`'s digest step needs; without it the name would still be registered but
 * the method would never come back. The name is the authority's own: `OSSL_DIGEST_PARAM_SIZE` is
 * `"size"` and the block size is asked under the literal `"blocksize"`.
 */
static int dg_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 32))
        return 0;
    p = OSSL_PARAM_locate(params, "blocksize");
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 64))
        return 0;
    return 1;
}

static const OSSL_DISPATCH dg_fns[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) dg_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) dg_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) dg_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) dg_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) dg_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) dg_get_params },
    { 0, NULL }
};

static int ssp_calls, ssp_saw, ssp_len;
static unsigned char ssp_bytes[16];

static void reset_ssp(void)
{
    ssp_calls = ssp_saw = ssp_len = 0;
    ERR_clear_error();
}

static int ssp_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const void *data = NULL;
    size_t len = 0;

    (void) vctx;
    ssp_calls++;
    p = OSSL_PARAM_locate_const(params, "signature");
    if (p != NULL && OSSL_PARAM_get_octet_string_ptr(p, &data, &len) && data != NULL) {
        ssp_saw++;
        ssp_len = (int) len;
        if (len > sizeof ssp_bytes)
            len = sizeof ssp_bytes;
        memcpy(ssp_bytes, data, len);
    }
    return 1;
}

static const OSSL_PARAM ssp_tab[] = {
    OSSL_PARAM_octet_string("signature", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ssp_settable_ctx_params(void *vctx, void *provctx)
{
    (void) vctx;
    (void) provctx;
    return ssp_tab;
}

static const OSSL_DISPATCH sig_setparams_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) sig_sign },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void)) ssp_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void)) ssp_settable_ctx_params },
    { 0, NULL }
};

/* ------------------------------------------------------------------ the two bodies of algorithms */

#define COURT_PROV "provider=court-pkey"

static const OSSL_ALGORITHM court_keymgmts[] = {
    { "COURT-SIGKEY:courtsigkey", COURT_PROV, kmgm_fns,
      "the probe's key type, and the one the key's preferred-signature name comes from" },
    { "COURT-PKEY:courtpkey", COURT_PROV, pn_fns,
      "the 7.4e key type: every parameter the accessors of this subphase read" },
    { "id-ecPublicKey:courtec", COURT_PROV, pk_gen_fns,
      "a generation-only key type under the object spelling `int_ctx_new` derives from `EC`" },
    { "rsaEncryption:courtrsa", COURT_PROV, pk_gen_fns,
      "the same for `RSA`, whose argument is a size_t" },
    { "COURT-GEN:courtgen", COURT_PROV, pk_gen_fns,
      "the control: a name the walk reads nothing for" },
    /*
     * Four more names, all `pn_fns`, and each exists for one road into `new_raw_key_int`'s
     * provider branch. The two legacy-type spellings do not name a key type at all: they fetch
     * `OBJ_nid2sn(type)` in the **default** library context, so these are also published there (see
     * `main`'s second registration), and each is chosen so that no other provider can answer it --
     * `UNDEF` is `OBJ_nid2sn(EVP_PKEY_NONE)` and nothing publishes it, `X448` is a name the
     * authority's default provider also has, and the measurement is that the probe's provider wins
     * for it (D190 records it). `EVP_PKEY_RSA`'s `rsaEncryption` is deliberately **not** one of
     * them: it is already the probe's *generation* key type, which `EVP_PKEY_Q_keygen("RSA", ...)`
     * needs, and two algorithms under one name list would leave the store to pick between them --
     * `EVP_PKEY_X448` is the same shape and does not collide.
     */
    { "UNDEF:courtrawex", COURT_PROV, pn_fns,
      "`OBJ_nid2sn(EVP_PKEY_NONE)`, so a raw constructor with type 0 has exactly one provider" },
    { "X448:courtx448", COURT_PROV, pn_fns,
      "`EVP_PKEY_X448`: the authority's `EVP_PKEY_asn1_find` *does* find `ossl_ecx448_asn1_meth`" },
    { "COURT-RAWKEY:courtrawkey", COURT_PROV, pn_fns,
      "the name the two `_ex` spellings are handed" },
    { "CMAC:courtrcmac", COURT_PROV, pn_fns,
      "`EVP_PKEY_new_CMAC_key`'s hardcoded name; its success arm needs the default context" },
    { NULL, NULL, NULL, NULL }
};

/*
 * The arms, and the reason each one exists rather than sharing a table with its neighbour:
 *
 *   `COURT-SIG`/`QON-FULL`   every callback; the success arm for all six init/operate pairs, and
 *                            the arm the plain (fetching) spellings resolve to because the keymgmt
 *                            answers `COURT-SIG` when `g_qon` is not moved.
 *   `SIG-Failing`            a distinct algorithm with the same table; `g_fail_ops` makes its
 *                            *operation* callbacks answer 0, so the FAILURE arm of the six
 *                            operate entry points is reachable with the init still succeeding.
 *   `SIG-Fb1`                carries the keymgmt's own name, which is what fallback 1 compares.
 *   `SIG-Fb2`                carries only its own preferred name, matched by fallback 2.
 *   `SIG-FbNone`             carries neither, so both fallbacks fail.
 *   `SIG-Qkt`                publishes `query_key_types`; the probe sets the array it answers.
 *   `SIG-NoSignInit`         refused by `sign_init`'s absence.
 *   `SIG-NoSmi`              refused by `sign_message_init`'s absence.
 *   `SIG-NoVerifyInit`       refused by `verify_init`'s absence.
 *   `SIG-NoVmi`              refused by `verify_message_init`'s absence.
 *   `SIG-NoVri`              refused by `verify_recover_init`'s absence.
 *   `SIG-MsgSign`            a message signer with no `sign`, so `EVP_PKEY_sign` on an armed
 *                            SIGNMSG operation reaches its own NULL arm.
 *   `SIG-MsgVerify`          the same for `EVP_PKEY_verify`.
 *   `SIG-SignMsgHalf`        `sign_message_init` with neither `update` nor `final`.
 *   `SIG-VerifyMsgHalf`      the same on the verification side.
 */
static const OSSL_ALGORITHM court_sigs[] = {
    { "COURT-SIG:QON-FULL:courtsigfull", COURT_PROV, sig_full_fns,
      "every callback" },
    { "SIG-Failing:QON-FAIL:courtsigfailing", COURT_PROV, sig_full_fns,
      "the operation callbacks answer 0" },
    { "SIG-Fb1:COURT-SIGKEY:courtsigfb1", COURT_PROV, sig_full_fns,
      "matched by the key's own type name" },
    { "SIG-Fb2:QON-FB2:courtsigfb2", COURT_PROV, sig_full_fns,
      "matched by the key's preferred operation name" },
    { "SIG-FbNone:QON-FBNONE:courtsigfbnone", COURT_PROV, sig_full_fns,
      "matched by neither fallback" },
    { "SIG-Qkt:QON-QKT:courtsigqkt", COURT_PROV, sig_qkt_fns,
      "answers query_key_types" },
    { "SIG-NoSignInit:QON-NSI:courtsignsi", COURT_PROV, sig_verify_only_fns,
      "refused: no sign_init" },
    { "SIG-NoSmi:QON-NSMI:courtsignsmi", COURT_PROV, sig_sign_only_fns,
      "refused: no sign_message_init" },
    { "SIG-NoVerifyInit:QON-NVI:courtnvi", COURT_PROV, sig_sign_only_fns,
      "refused: no verify_init" },
    { "SIG-NoVmi:QON-NVMI:courtnvmi", COURT_PROV, sig_verify_only_fns,
      "refused: no verify_message_init" },
    { "SIG-NoVri:QON-NVRI:courtnvri", COURT_PROV, sig_verify_only_fns,
      "refused: no verify_recover_init" },
    { "SIG-MsgSign:QON-MS:courtsigms", COURT_PROV, sig_msgsign_fns,
      "refused: a message signer with no sign" },
    { "SIG-MsgVerify:QON-MV:courtsigmv", COURT_PROV, sig_msgverify_fns,
      "refused: a message verifier with no verify" },
    { "SIG-SignMsgHalf:QON-SMH:courtsigsmh", COURT_PROV, sig_signmsghalf_fns,
      "refused: sign_message_init without update or final" },
    { "SIG-VerifyMsgHalf:QON-VMH:courtsigvmh", COURT_PROV, sig_verifymsghalf_fns,
      "refused: verify_message_init without update or final" },
    { "SIG-SetParams:QON-SSP:courtsigssp", COURT_PROV, sig_setparams_fns,
      "publishes set_ctx_params, so `EVP_PKEY_CTX_set_signature`'s parameter is observable" },
    /* 7.4f: the digest signature methods. Each is selected by moving the keymgmt's
     * `query_operation_name` answer (`g_qon`), which is the one lever `do_sigver_init` reads. */
    { "DSG-FULL:QON-DSF:courtdsgfull", COURT_PROV, dsg_full_fns,
      "every digest callback" },
    { "DSG-NOSTREAM:QON-DSN:courtdsgnostream", COURT_PROV, dsg_nostream_fns,
      "a one-shot: no digest_sign_update/final, no digest_verify_update/final" },
    { "DSG-SIGNONLY:QON-DSO:courtdsgsignonly", COURT_PROV, dsg_signonly_fns,
      "refused by digest_verify_init's absence" },
    { "DSG-VERIFYONLY:QON-DVO:courtdsgverifyonly", COURT_PROV, dsg_verifyonly_fns,
      "refused by digest_sign_init's absence" },
    { "DSG-NONEWCTX:QON-DNN:courtdsgnonewctx", COURT_PROV, dsg_nonewctx_fns,
      "newctx answers NULL" },
    { "DSG-NODUP:QON-DND:courtdsgnodup", COURT_PROV, dsg_nodup_fns,
      "no dupctx, so a final with a buffer runs on the original" },
    { "DSG-SETMD:QON-DSM:courtdsgsetsmd", COURT_PROV, dsg_setmd_fns,
      "the md-parameter pair, for the EVP_MD_CTX_set_params redirect" },
    { NULL, NULL, NULL, NULL }
};

/* The digest whose **name** is all that matters: it is what `legacy_asn1_ctrl_to_param` fetches so
 * that the namemap learns `SHA256`, and it is never called. Five of the six counted callbacks are
 * present, which is what the structural check admits. */
static const OSSL_ALGORITHM court_digests[] = {
    { "SHA256:court-sha256", COURT_PROV, dg_fns,
      "a digest name, so the namemap can resolve one back to a NID" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return court_keymgmts;
    if (operation_id == OSSL_OP_SIGNATURE)
        return court_sigs;
    if (operation_id == OSSL_OP_DIGEST)
        return court_digests;
    return NULL;
}

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_query },
    { 0, NULL }
};

static int court_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_dispatch;
    *provctx = (void *) (size_t) 1;
    return 1;
}

/* ------------------------------------------------------------------ main */

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *prov, *prov_default;
    EVP_KEYMGMT *keymgmt, *again;
    EVP_PKEY_CTX *fctx, *sctx, *kctx, *ectx;
    EVP_PKEY *pkey = NULL, *empty = NULL;
    EVP_SIGNATURE *s;
    OSSL_PARAM params[1];
    unsigned char out[32];
    unsigned char msg[4] = { 't', 'b', 's', 0 };
    size_t len;
    int ret;

    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }
    sayn("add_builtin", OSSL_PROVIDER_add_builtin(ctx, "court-pkey", court_init));
    prov = OSSL_PROVIDER_load(ctx, "court-pkey");
    sayn("load", prov != NULL ? 1 : 0);
    if (prov == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }

    /*
     * The **same** provider, in the default library context. Three entry points cannot be given a
     * context and hardcode NULL instead -- `EVP_PKEY_new_CMAC_key` and the two legacy-type raw
     * constructors -- so their provider branch resolves `"CMAC"` or `OBJ_nid2sn(type)` there. The
     * measurement that makes this deterministic is below and in D190: with this provider present
     * the authority's own default provider is never activated for those names, so both sides answer
     * from the probe. Nothing above this line touches the default context, so the arms before it
     * are unaffected.
     */
    sayn("add_builtin_default", OSSL_PROVIDER_add_builtin(NULL, "court-pkey", court_init));
    prov_default = OSSL_PROVIDER_load(NULL, "court-pkey");
    sayn("load_default", prov_default != NULL ? 1 : 0);

    /*
     * ---- the key ----
     *
     * `EVP_PKEY_fromdata` is the only public door that gives a provider key *key data*, and key
     * data is what `evp_pkey_export_to_provider` exports. A key set with
     * `EVP_PKEY_set_type_by_keymgmt` alone has a method and no data, which is a state worth keeping
     * because it is one of the three ways into `legacy:`.
     */
    reset_c();
    keymgmt = EVP_KEYMGMT_fetch(ctx, "COURT-SIGKEY", NULL);
    sayp("key.keymgmt", keymgmt);
    fctx = EVP_PKEY_CTX_new_from_name(ctx, "COURT-SIGKEY", NULL);
    sayp("key.fromdata_ctx", fctx);
    sayr("key.fromdata_init", EVP_PKEY_fromdata_init(fctx));
    sayr("key.fromdata", EVP_PKEY_fromdata(fctx, &pkey, EVP_PKEY_KEYPAIR, NULL));
    sayn("key.pkey", pkey != NULL ? 1 : 0);
    say_k("key.vec");

    sctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, NULL);
    sayp("key.op_ctx", sctx);
    if (pkey == NULL || sctx == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }

    empty = EVP_PKEY_new();
    sayr("empty.set_type", EVP_PKEY_set_type_by_keymgmt(empty, keymgmt));
    ectx = EVP_PKEY_CTX_new_from_pkey(ctx, empty, NULL);
    sayp("empty.op_ctx", ectx);

    /* A context with a method and no key at all -- the `EVP_PKEY_CTX_new_from_name` shape. */
    kctx = EVP_PKEY_CTX_new_from_name(ctx, "COURT-SIGKEY", NULL);
    sayp("keyless.op_ctx", kctx);

    /*
     * ---- 1. the NULL context, eighteen times ----
     *
     * Every one of the eighteen tests its context pointer first, and all eighteen answer `-1` with
     * `ERR_R_PASSED_NULL_PARAMETER`; the *line* is what tells them apart, which is why the
     * transcript carries it.
     */
    len = sizeof out;
    sayr("null.sign_init", EVP_PKEY_sign_init(NULL));
    sayr("null.sign_init_ex", EVP_PKEY_sign_init_ex(NULL, NULL));
    sayr("null.sign_init_ex2", EVP_PKEY_sign_init_ex2(NULL, NULL, NULL));
    sayr("null.sign_message_init", EVP_PKEY_sign_message_init(NULL, NULL, NULL));
    sayr("null.sign_message_update", EVP_PKEY_sign_message_update(NULL, msg, 1));
    sayr("null.sign_message_final", EVP_PKEY_sign_message_final(NULL, out, &len));
    sayr("null.sign", EVP_PKEY_sign(NULL, out, &len, msg, 1));
    sayr("null.verify_init", EVP_PKEY_verify_init(NULL));
    sayr("null.verify_init_ex", EVP_PKEY_verify_init_ex(NULL, NULL));
    sayr("null.verify_init_ex2", EVP_PKEY_verify_init_ex2(NULL, NULL, NULL));
    sayr("null.verify_message_init", EVP_PKEY_verify_message_init(NULL, NULL, NULL));
    sayr("null.verify_message_update", EVP_PKEY_verify_message_update(NULL, msg, 1));
    sayr("null.verify_message_final", EVP_PKEY_verify_message_final(NULL));
    sayr("null.verify", EVP_PKEY_verify(NULL, msg, 1, msg, 1));
    sayr("null.verify_recover_init", EVP_PKEY_verify_recover_init(NULL));
    sayr("null.verify_recover_init_ex", EVP_PKEY_verify_recover_init_ex(NULL, NULL));
    sayr("null.verify_recover_init_ex2", EVP_PKEY_verify_recover_init_ex2(NULL, NULL, NULL));
    sayr("null.verify_recover", EVP_PKEY_verify_recover(NULL, out, &len, msg, 1));

    /*
     * ---- 2. the operation guard ----
     *
     * A fresh context is `EVP_PKEY_OP_UNDEFINED`, so all seven entry points answer
     * `OPERATION_NOT_INITIALIZED` -- and they answer it *before* they look at the algorithm
     * context, which the next block makes observable by calling them on a context that has an
     * operation and no algorithm context.
     */
    sayr("opguard.sign", EVP_PKEY_sign(sctx, out, &len, msg, 1));
    sayr("opguard.sign_message_update", EVP_PKEY_sign_message_update(sctx, msg, 1));
    sayr("opguard.sign_message_final", EVP_PKEY_sign_message_final(sctx, out, &len));
    sayr("opguard.verify", EVP_PKEY_verify(sctx, msg, 1, msg, 1));
    sayr("opguard.verify_message_update", EVP_PKEY_verify_message_update(sctx, msg, 1));
    sayr("opguard.verify_message_final", EVP_PKEY_verify_message_final(sctx));
    sayr("opguard.verify_recover", EVP_PKEY_verify_recover(sctx, out, &len, msg, 1));

    /* Each of the five inits accepts a context whose operation is the *other* one of its pair,
     * because all five begin by calling `evp_pkey_ctx_free_old_ops` and then storing the new
     * operation. So a context armed for signing still answers the verification entry points'
     * operation test with the wrong-operation reason. */
    sayr("opguard.sign_init", EVP_PKEY_sign_init(sctx));
    sayr("opguard.sign_on_armed", EVP_PKEY_sign(sctx, out, &len, msg, 1));
    sayr("opguard.sign_message_update_on_sign", EVP_PKEY_sign_message_update(sctx, msg, 1));
    sayr("opguard.sign_message_final_on_sign", EVP_PKEY_sign_message_final(sctx, out, &len));
    sayr("opguard.verify_on_sign", EVP_PKEY_verify(sctx, msg, 1, msg, 1));
    sayr("opguard.verify_message_update_on_sign", EVP_PKEY_verify_message_update(sctx, msg, 1));
    sayr("opguard.verify_message_final_on_sign", EVP_PKEY_verify_message_final(sctx));
    sayr("opguard.verify_recover_on_sign", EVP_PKEY_verify_recover(sctx, out, &len, msg, 1));

    /* `EVP_PKEY_verify` accepts `EVP_PKEY_OP_VERIFY` *or* `EVP_PKEY_OP_VERIFYMSG`, so a context
     * armed for one-shot signing is not enough: `EVP_PKEY_sign` is the one that accepts the
     * message spelling, and it does so. */
    sayr("opguard.sign_on_signmsg_later", EVP_PKEY_sign_message_init(sctx, NULL, NULL));
    sayr("opguard.sign_on_signmsg", EVP_PKEY_sign(sctx, out, &len, msg, 1));

    /*
     * ---- 3. the two `EVP_R_NO_KEY_SET` arms ----
     *
     * The two are different sites with the same reason and the same answer: the pre-fetched branch
     * tests `ctx->pkey` before anything else, and the fetching branch tests it after the legacy
     * test. Both leave `ret` at 0, and both take `err:`, so the context ends `UNDEFINED`.
     */
    sayr("nokey.sign_init", EVP_PKEY_sign_init(kctx));
    s = EVP_SIGNATURE_fetch(ctx, "COURT-SIG", NULL);
    sayp("nokey.algo", s);
    sayr("nokey.sign_init_ex2", EVP_PKEY_sign_init_ex2(kctx, s, NULL));
    EVP_SIGNATURE_free(s);

    /*
     * ---- 4. the success path, one callback at a time ----
     *
     * `COURT-SIG` resolves through the key's preferred name, which is the fetching branch: nothing
     * here checks a key type, and the counters say which callbacks the tail armed.
     */
    reset_c();
    sayr("full.sign_init", EVP_PKEY_sign_init(sctx));
    say_c("full.sign_init.vec");
    reset_c();
    len = sizeof out;
    sayr("full.sign", EVP_PKEY_sign(sctx, out, &len, msg, 3));
    sayn("full.sign.len_out", (long long) len);
    say_c("full.sign.vec");

    /* The output buffer is absent: the provider must see length **0**, not a skipped call. */
    reset_c();
    len = sizeof out;
    sayr("full.sign_no_out", EVP_PKEY_sign(sctx, NULL, &len, msg, 3));
    say_c("full.sign_no_out.vec");

    /* An `_ex` spelling hands the method the caller's params, and the init counters say so. */
    reset_c();
    params[0] = OSSL_PARAM_construct_end();
    sayr("full.sign_init_ex_params", EVP_PKEY_sign_init_ex(sctx, params));
    say_c("full.sign_init_ex_params.vec");

    reset_c();
    sayr("full.verify_init", EVP_PKEY_verify_init(sctx));
    sayr("full.verify", EVP_PKEY_verify(sctx, msg, 3, msg, 3));
    say_c("full.verify.vec");

    reset_c();
    sayr("full.verify_recover_init", EVP_PKEY_verify_recover_init(sctx));
    len = sizeof out;
    sayr("full.verify_recover", EVP_PKEY_verify_recover(sctx, out, &len, msg, 3));
    sayn("full.verify_recover.len_out", (long long) len);
    say_c("full.verify_recover.vec");

    reset_c();
    sayr("full.sign_message_init", EVP_PKEY_sign_message_init(sctx, NULL, NULL));
    sayr("full.sign_message_update", EVP_PKEY_sign_message_update(sctx, msg, 3));
    len = sizeof out;
    sayr("full.sign_message_final", EVP_PKEY_sign_message_final(sctx, out, &len));
    say_c("full.sign_message.vec");

    reset_c();
    sayr("full.verify_message_init", EVP_PKEY_verify_message_init(sctx, NULL, NULL));
    sayr("full.verify_message_update", EVP_PKEY_verify_message_update(sctx, msg, 3));
    sayr("full.verify_message_final", EVP_PKEY_verify_message_final(sctx));
    say_c("full.verify_message.vec");

    /*
     * The same six pairs through the pre-fetched spellings. Now the key-type check *does* run, and
     * it passes through fallback 2 because the keymgmt answers the arm's own preferred name.
     */
    g_qon = "QON-FULL";
    s = EVP_SIGNATURE_fetch(ctx, "COURT-SIG", NULL);
    sayp("prefetched.algo", s);
    reset_c();
    sayr("prefetched.sign_init_ex2", EVP_PKEY_sign_init_ex2(sctx, s, NULL));
    say_c("prefetched.sign_init_ex2.vec");
    reset_c();
    len = sizeof out;
    sayr("prefetched.sign", EVP_PKEY_sign(sctx, out, &len, msg, 3));
    say_c("prefetched.sign.vec");
    reset_c();
    sayr("prefetched.verify_init_ex2", EVP_PKEY_verify_init_ex2(sctx, s, NULL));
    sayr("prefetched.verify", EVP_PKEY_verify(sctx, msg, 3, msg, 3));
    say_c("prefetched.verify.vec");
    reset_c();
    sayr("prefetched.verify_recover_init_ex2", EVP_PKEY_verify_recover_init_ex2(sctx, s, NULL));
    len = sizeof out;
    sayr("prefetched.verify_recover", EVP_PKEY_verify_recover(sctx, out, &len, msg, 3));
    say_c("prefetched.verify_recover.vec");
    reset_c();
    sayr("prefetched.sign_message_init", EVP_PKEY_sign_message_init(sctx, s, NULL));
    sayr("prefetched.sign_message_update", EVP_PKEY_sign_message_update(sctx, msg, 3));
    len = sizeof out;
    sayr("prefetched.sign_message_final", EVP_PKEY_sign_message_final(sctx, out, &len));
    say_c("prefetched.sign_message.vec");
    reset_c();
    sayr("prefetched.verify_message_init", EVP_PKEY_verify_message_init(sctx, s, NULL));
    sayr("prefetched.verify_message_update", EVP_PKEY_verify_message_update(sctx, msg, 3));
    sayr("prefetched.verify_message_final", EVP_PKEY_verify_message_final(sctx));
    say_c("prefetched.verify_message.vec");
    EVP_SIGNATURE_free(s);
    g_qon = "COURT-SIG";

    /*
     * ---- 5. the failing operation callbacks ----
     *
     * The init answers 1 and the operation answers 0, which is the only way the FAILURE raise is
     * distinguishable from the NOT_SUPPORTED one: both are `-2` and both name a clause, but the
     * clause and the reason differ.
     */
    g_fail_ops = 1;
    reset_c();
    sayr("failing.sign_init", EVP_PKEY_sign_init(sctx));
    len = sizeof out;
    sayr("failing.sign", EVP_PKEY_sign(sctx, out, &len, msg, 3));
    sayr("failing.verify_init", EVP_PKEY_verify_init(sctx));
    sayr("failing.verify", EVP_PKEY_verify(sctx, msg, 3, msg, 3));
    sayr("failing.verify_recover_init", EVP_PKEY_verify_recover_init(sctx));
    len = sizeof out;
    sayr("failing.verify_recover", EVP_PKEY_verify_recover(sctx, out, &len, msg, 3));
    sayr("failing.sign_message_init", EVP_PKEY_sign_message_init(sctx, NULL, NULL));
    sayr("failing.sign_message_update", EVP_PKEY_sign_message_update(sctx, msg, 3));
    len = sizeof out;
    sayr("failing.sign_message_final", EVP_PKEY_sign_message_final(sctx, out, &len));
    sayr("failing.verify_message_init", EVP_PKEY_verify_message_init(sctx, NULL, NULL));
    sayr("failing.verify_message_update", EVP_PKEY_verify_message_update(sctx, msg, 3));
    sayr("failing.verify_message_final", EVP_PKEY_verify_message_final(sctx));
    say_c("failing.vec");
    g_fail_ops = 0;

    /*
     * ---- 6. one arm per missing callback ----
     *
     * Each is reached through the pre-fetched spelling with `g_qon` moved to the arm's own
     * preferred name, so the key-type check passes through fallback 2 and the refusal that follows
     * is the one under test. The `newctx` counter has already moved and the `free` counter moves
     * *after* the refusal, because the authority frees the method's context on its way to `err:`.
     */
    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-NoSignInit", NULL);
    sayp("missing.no_sign_init.algo", s);
    g_qon = "QON-NSI";
    sayr("missing.sign_init", EVP_PKEY_sign_init_ex2(sctx, s, NULL));
    say_c("missing.sign_init.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-NoSmi", NULL);
    g_qon = "QON-NSMI";
    sayr("missing.sign_message_init", EVP_PKEY_sign_message_init(sctx, s, NULL));
    say_c("missing.sign_message_init.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-NoVerifyInit", NULL);
    g_qon = "QON-NVI";
    sayr("missing.verify_init", EVP_PKEY_verify_init_ex2(sctx, s, NULL));
    say_c("missing.verify_init.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-NoVmi", NULL);
    g_qon = "QON-NVMI";
    sayr("missing.verify_message_init", EVP_PKEY_verify_message_init(sctx, s, NULL));
    say_c("missing.verify_message_init.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-NoVri", NULL);
    g_qon = "QON-NVRI";
    sayr("missing.verify_recover_init", EVP_PKEY_verify_recover_init_ex2(sctx, s, NULL));
    say_c("missing.verify_recover_init.vec");
    EVP_SIGNATURE_free(s);

    /*
     * The two operation callbacks a message-only method leaves absent. The init *succeeds*, so the
     * refusal comes from the operate entry point and its own clause -- which is the arm a court
     * that only drove well-formed methods would never see.
     */
    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-MsgSign", NULL);
    g_qon = "QON-MS";
    sayr("missing.msg_sign_init", EVP_PKEY_sign_message_init(sctx, s, NULL));
    sayr("missing.msg_sign_update", EVP_PKEY_sign_message_update(sctx, msg, 3));
    len = sizeof out;
    sayr("missing.msg_sign_final", EVP_PKEY_sign_message_final(sctx, out, &len));
    sayr("missing.sign_after_msg_init", EVP_PKEY_sign(sctx, out, &len, msg, 3));
    say_c("missing.msg_sign.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-MsgVerify", NULL);
    g_qon = "QON-MV";
    sayr("missing.msg_verify_init", EVP_PKEY_verify_message_init(sctx, s, NULL));
    sayr("missing.msg_verify_update", EVP_PKEY_verify_message_update(sctx, msg, 3));
    sayr("missing.msg_verify_final", EVP_PKEY_verify_message_final(sctx));
    sayr("missing.verify_after_msg_init", EVP_PKEY_verify(sctx, msg, 3, msg, 3));
    say_c("missing.msg_verify.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-SignMsgHalf", NULL);
    g_qon = "QON-SMH";
    sayr("missing.signmsg_half_init", EVP_PKEY_sign_message_init(sctx, s, NULL));
    sayr("missing.signmsg_half_update", EVP_PKEY_sign_message_update(sctx, msg, 3));
    len = sizeof out;
    sayr("missing.signmsg_half_final", EVP_PKEY_sign_message_final(sctx, out, &len));
    say_c("missing.signmsg_half.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-VerifyMsgHalf", NULL);
    g_qon = "QON-VMH";
    sayr("missing.verifymsg_half_init", EVP_PKEY_verify_message_init(sctx, s, NULL));
    sayr("missing.verifymsg_half_update", EVP_PKEY_verify_message_update(sctx, msg, 3));
    sayr("missing.verifymsg_half_final", EVP_PKEY_verify_message_final(sctx));
    say_c("missing.verifymsg_half.vec");
    EVP_SIGNATURE_free(s);

    /*
     * ---- 7. the `query_key_types` walk ----
     *
     * `SIG-Qkt` publishes the callback, so the pre-fetched branch walks the array it answers. Three
     * answers, three outcomes, and the two refusals take `end:` rather than `err:` -- so no
     * algorithm context is ever created and neither the `newctx` nor the `free` counter moves.
     */
    s = EVP_SIGNATURE_fetch(ctx, "SIG-Qkt", NULL);
    sayp("qkt.algo", s);
    g_qon = "QON-QKT";

    reset_c();
    g_keytypes = (const char **) kt_match;
    sayr("qkt.match", EVP_PKEY_sign_init_ex2(sctx, s, NULL));
    say_c("qkt.match.vec");

    reset_c();
    g_keytypes = (const char **) kt_nomatch;
    sayr("qkt.no_match", EVP_PKEY_sign_init_ex2(sctx, s, NULL));
    say_c("qkt.no_match.vec");

    reset_c();
    g_keytypes = (const char **) kt_empty;
    sayr("qkt.empty", EVP_PKEY_sign_init_ex2(sctx, s, NULL));
    say_c("qkt.empty.vec");
    g_keytypes = NULL;
    EVP_SIGNATURE_free(s);

    /*
     * ---- 8. the two fallbacks, and the preferred-name lookup ----
     */
    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-Fb1", NULL);
    g_qon = "COURT-SIGKEY";
    sayr("fallback.by_key_type_name", EVP_PKEY_sign_init_ex2(sctx, s, NULL));
    say_c("fallback.by_key_type_name.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-Fb2", NULL);
    g_qon = "QON-FB2";
    sayr("fallback.by_preferred_name", EVP_PKEY_sign_init_ex2(sctx, s, NULL));
    say_c("fallback.by_preferred_name.vec");
    EVP_SIGNATURE_free(s);

    reset_c();
    s = EVP_SIGNATURE_fetch(ctx, "SIG-FbNone", NULL);
    g_qon = "QON-FB2";
    sayr("fallback.neither", EVP_PKEY_sign_init_ex2(sctx, s, NULL));
    say_c("fallback.neither.vec");
    EVP_SIGNATURE_free(s);

    /*
     * The keymgmt's `query_operation_name` is present but answers NULL, and the util falls back to
     * the method's own type name -- so the fetching branch asks for `COURT-SIGKEY`, which
     * `SIG-Fb1` carries. A transcription that read NULL as "no name" would refuse the init.
     */
    reset_c();
    g_qon = NULL;
    sayr("fallback.qon_answers_null", EVP_PKEY_sign_init(sctx));
    say_c("fallback.qon_answers_null.vec");

    /*
     * ---- 9. the `legacy:` label, and the arm it makes reachable ----
     *
     * `g_qon` names an algorithm no provider publishes, so the second iteration cannot produce one
     * and the init leaves for `legacy:`. The label frees the keymgmt, raises
     * `OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` and returns `-2` -- **without resetting
     * `ctx->operation`** -- so the context is left armed with no algorithm context and the three
     * one-shot entry points take their own NULL-algorithm-context arm next.
     */
    g_qon = "QON-NO-SUCH-SIGNATURE";
    reset_c();
    sayr("legacy.sign_init", EVP_PKEY_sign_init(sctx));
    say_c("legacy.sign_init.vec");
    sayr("legacy.armed_then_sign", EVP_PKEY_sign(sctx, out, &len, msg, 3));
    sayr("legacy.verify_init", EVP_PKEY_verify_init(sctx));
    sayr("legacy.armed_then_verify", EVP_PKEY_verify(sctx, msg, 3, msg, 3));
    sayr("legacy.verify_recover_init", EVP_PKEY_verify_recover_init(sctx));
    sayr("legacy.armed_then_verify_recover",
         EVP_PKEY_verify_recover(sctx, out, &len, msg, 3));
    /* And away from the armed operation: `EVP_PKEY_sign` accepts only the two signing
     * operations, so a context armed for recovery answers the operation guard instead. */
    sayr("legacy.sign_init_again", EVP_PKEY_sign_init(sctx));
    sayr("legacy.armed_then_sign_once_more", EVP_PKEY_sign(sctx, out, &len, msg, 3));

    /*
     * The post-loop entry to `legacy:`: the method is fetched, the key has a method and no key
     * data, so the export answers NULL on both iterations and the init falls through with a live
     * keymgmt to free. The authority's own comment calls this out, and the counter vector shows
     * the two fetches.
     */
    g_qon = "COURT-SIG";
    reset_c();
    sayr("legacy.empty_key_init", EVP_PKEY_sign_init(ectx));
    say_c("legacy.empty_key_init.vec");
    sayr("legacy.empty_key_then_sign", EVP_PKEY_sign(ectx, out, &len, msg, 3));

    /*
     * The pre-fetched branch's other exit, and the one that is neither a refusal nor a success: a
     * method *is* handed in and the key cannot be exported to it, so the authority jumps to `end:`
     * with `ret` still **0** and raises nothing at all. Two things follow, and both are
     * observations: the answer is `0` rather than the `-2` the fallback refusals give, and the
     * context is left **armed** -- `end:` does not reset the operation either -- so the one-shot
     * entry point takes its NULL-algorithm-context arm next.
     */
    s = EVP_SIGNATURE_fetch(ctx, "COURT-SIG", NULL);
    reset_c();
    sayr("prefetched.end_no_export", EVP_PKEY_sign_init_ex2(ectx, s, NULL));
    sayr("prefetched.end_no_export_then_sign", EVP_PKEY_sign(ectx, out, &len, msg, 3));
    say_c("prefetched.end_no_export.vec");
    EVP_SIGNATURE_free(s);

    /*
     * Four sites are reached only by a call this probe must not make, and the reason is the same
     * for all four: the stream entry points read `ctx->op.sig.signature` with no test, and a
     * context left armed by a `legacy:` refusal has none.
     */
    printf("stream_update_on_legacy_armed=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("stream_final_on_legacy_armed=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("stream_verify_update_on_legacy_armed=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("stream_verify_final_on_legacy_armed=NOT_MEASURED_AUTHORITY_FAULTS\n");
    /* Nothing dereferences a `pmeth` this crate does not have, so nothing is claimed about it. */
    printf("legacy_pmeth_switch=NOT_MEASURED_PMETH_IS_PHASE_8\n");
    printf("verify_recover_null_callback=NOT_MEASURED_UNREACHABLE_STRUCTURAL_CHECK\n");

    /*
     * ============================ 7.4e: `p_lib.c`'s provider half ============================
     *
     * The arms below are grouped by the question each answers, and every one of them is a
     * relation, a presence answer, a counter vector or a bounded byte comparison. Two structural
     * facts shape the whole block:
     *
     *   * **`COURT-PKEY`'s answers are globals**, so "the provider publishes this parameter" and
     *     "it does not" are two states of one key type rather than two key types. The cache arms
     *     are the ones that need this most: `EVP_PKEY_get_bits` answers `0` because the *cache* was
     *     never filled, and the cache is filled once per assignment from four parameters, so the
     *     three answers a provider can give (values, silence with a success, a failure) are three
     *     distinct cache states.
     *   * **a key's method is immutable once assigned**, so every arm that needs a different
     *     provider answer builds its own key. That is why there is more than one `np`.
     */
    {
        EVP_PKEY *np = NULL, *np_silent = NULL, *np_fail = NULL, *rk = NULL;
        EVP_PKEY *nblank = EVP_PKEY_new();
        EVP_PKEY *ntarget = EVP_PKEY_new();
        EVP_PKEY *nparam = EVP_PKEY_new();
        EVP_PKEY_CTX *nctx = EVP_PKEY_CTX_new_from_name(ctx, "COURT-PKEY", NULL);
        EVP_PKEY_CTX *ngctx;
        EVP_PKEY *qk = NULL;
        EVP_SIGNATURE *ssig;
        OSSL_PARAM np_params[2], rk_params[3];
        unsigned char raw_priv[4] = { 1, 2, 3, 4 };
        unsigned char raw_pub[4] = { 5, 6, 7, 8 };
        unsigned char raw_out[8];
        size_t raw_len;
        unsigned char enc_in[4] = { 'e', 'n', 'c', '1' };
        unsigned char *enc_out;
        unsigned char sig_in[4] = { 's', 'i', 'g', '1' };
        char grp[80];
        size_t grp_len;
        int nid;
        X509_ALGOR alg_in, alg_out;
        ASN1_STRING alg_str;
        ASN1_TYPE alg_type;

        sayp("pkey.new_ctx", nctx);
        /*
         * The generation context is asked for by the name `EVP_PKEY_Q_keygen`'s walk reads an
         * argument for, and `int_ctx_new` rewrites that name before fetching: `evp_pkey_name2type(
         * "EC")` is `EVP_PKEY_EC`, so the fetch is for `OBJ_nid2sn(EVP_PKEY_EC)` -- which is why the
         * probe's generation key type is published under the *object* spelling rather than under
         * the name the caller used. A transcript that got this wrong would compare a fetch that
         * succeeded against one that failed, which is exactly what the first run of this court did.
         */
        ngctx = EVP_PKEY_CTX_new_from_name(ctx, "EC", NULL);
        sayp("pkey.new_gen_ctx", ngctx);
        sayp("pkey.blank", nblank);

        /*
         * ---- 10. the cache, and the three states a provider can leave it in ----
         */
        np_params[0] = OSSL_PARAM_construct_octet_string("priv", raw_priv, sizeof raw_priv);
        np_params[1] = OSSL_PARAM_construct_end();
        reset_pn();
        sayr("parms.fromdata_init", EVP_PKEY_fromdata_init(nctx));
        sayr("parms.fromdata", EVP_PKEY_fromdata(nctx, &np, EVP_PKEY_KEYPAIR, np_params));
        sayp("parms.key", np);
        say_pn("parms.vec");
        sayr("cache.bits", EVP_PKEY_get_bits(np));
        sayr("cache.security_bits", EVP_PKEY_get_security_bits(np));
        sayr("cache.security_category", EVP_PKEY_get_security_category(np));
        sayr("cache.size", EVP_PKEY_get_size(np));

        /* The three "there is no key" answers; the two NULL ones are the same shape as the blank
         * one only where the authority says so, which is why all three are here. */
        sayr("cache.null.bits", EVP_PKEY_get_bits(NULL));
        sayr("cache.null.security_bits", EVP_PKEY_get_security_bits(NULL));
        sayr("cache.null.security_category", EVP_PKEY_get_security_category(NULL));
        sayr("cache.blank.bits", EVP_PKEY_get_bits(nblank));
        sayr("cache.blank.security_bits", EVP_PKEY_get_security_bits(nblank));
        sayr("cache.blank.security_category", EVP_PKEY_get_security_category(nblank));

        /* A provider that answers `get_params` with **success and nothing filled**: the cache is
         * written with the function's own initial values, which is the only way `security_category`
         * can be -1 on a key that exists. */
        g_pn_get_silent = 1;
        sayr("parms.silent_fromdata_init", EVP_PKEY_fromdata_init(nctx));
        sayr("parms.silent_fromdata", EVP_PKEY_fromdata(nctx, &np_silent, EVP_PKEY_KEYPAIR, np_params));
        g_pn_get_silent = 0;
        sayr("cache.silent.bits", EVP_PKEY_get_bits(np_silent));
        sayr("cache.silent.security_bits", EVP_PKEY_get_security_bits(np_silent));
        sayr("cache.silent.security_category", EVP_PKEY_get_security_category(np_silent));
        sayr("cache.silent.size", EVP_PKEY_get_size(np_silent));

        /* A provider that **fails** `get_params`: the cache keeps the zeros it was allocated with,
         * so `security_category` is 0 rather than -1. The two are the same refusal from the
         * accessor and different observations of the cache. */
        g_pn_get_fails = 1;
        sayr("parms.fail_fromdata_init", EVP_PKEY_fromdata_init(nctx));
        sayr("parms.fail_fromdata", EVP_PKEY_fromdata(nctx, &np_fail, EVP_PKEY_KEYPAIR, np_params));
        g_pn_get_fails = 0;
        sayr("cache.fail.bits", EVP_PKEY_get_bits(np_fail));
        sayr("cache.fail.security_category", EVP_PKEY_get_security_category(np_fail));

        /*
         * ---- 11. `EVP_PKEY_get_id`, `_get_base_id` and `_get0` ----
         *
         * The `-1` is `EVP_PKEY_KEYMGMT`, the pseudo-NID that says "provider side"; `get_base_id`
         * answers `EVP_PKEY_type(-1)`, which is `NID_undef` because no method table names it. The
         * blank key's `type` is `EVP_PKEY_NONE` and its `get_base_id` is `NID_undef` too -- so the
         * two differ in `get_id` and agree in `get_base_id`, which is the observation.
         */
        sayr("obj.provider_id", EVP_PKEY_get_id(np));
        sayr("obj.provider_base_id", EVP_PKEY_get_base_id(np));
        sayr("obj.blank_id", EVP_PKEY_get_id(nblank));
        sayr("obj.blank_base_id", EVP_PKEY_get_base_id(nblank));
        sayp("obj.provider_get0", EVP_PKEY_get0(np));
        sayp("obj.blank_get0", EVP_PKEY_get0(nblank));
        sayp("obj.null_get0", EVP_PKEY_get0(NULL));

        /*
         * ---- 12. parameters present, copied and compared ----
         */
        sayr("miss.provider", EVP_PKEY_missing_parameters(np));
        g_pn_has_data = 0;
        sayr("miss.provider_absent", EVP_PKEY_missing_parameters(np));
        g_pn_has_data = 1;
        sayr("miss.blank", EVP_PKEY_missing_parameters(nblank));
        sayr("miss.null", EVP_PKEY_missing_parameters(NULL));

        /* A blank target whose *empty* key data reports no parameters takes the copy. */
        g_pn_has_empty = 0;
        reset_pn();
        sayr("copy.to_blank", EVP_PKEY_copy_parameters(ntarget, np));
        say_pn("copy.to_blank.vec");
        /* It has key data now, so the same call takes the comparison arm. */
        reset_pn();
        sayr("copy.agree", EVP_PKEY_copy_parameters(ntarget, np));
        say_pn("copy.agree.vec");
        g_pn_match = 0;
        sayr("copy.disagree", EVP_PKEY_copy_parameters(ntarget, np));
        g_pn_match = 1;
        g_pn_has_data = 0;
        sayr("copy.from_missing", EVP_PKEY_copy_parameters(ntarget, np));
        g_pn_has_data = 1;
        sayr("copy.from_blank", EVP_PKEY_copy_parameters(ntarget, nblank));
        /* A blank target whose empty key data *does* report parameters goes the other way. */
        g_pn_has_empty = 1;
        sayr("copy.to_blank_params_present", EVP_PKEY_copy_parameters(nparam, np));
        g_pn_has_empty = 0;

        /* `can_sign` is about the *provider*, not the key: the name the key type prefers decides
         * whether a signature can be fetched at all. */
        g_pn_qon = "COURT-SIG";
        sayr("cansign.provider", EVP_PKEY_can_sign(np));
        g_pn_qon = "NO-SUCH-SIGNATURE";
        sayr("cansign.no_signature", EVP_PKEY_can_sign(np));
        g_pn_qon = "COURT-SIG";
        sayr("cansign.blank", EVP_PKEY_can_sign(nblank));

        /*
         * ---- 13. the encoded public key, as a round trip and as four refusals ----
         */
        sayr("enc.set1", EVP_PKEY_set1_encoded_public_key(np, enc_in, sizeof enc_in));
        enc_out = NULL;
        raw_len = EVP_PKEY_get1_encoded_public_key(np, &enc_out);
        sayn("enc.get1_len", (long long) raw_len);
        sayn("enc.get1_match",
             enc_out != NULL && raw_len == sizeof enc_in
             && memcmp(enc_out, enc_in, sizeof enc_in) == 0);
        OPENSSL_free(enc_out);

        g_pn_no_encpub = 1;
        enc_out = enc_in; /* a pointer this probe holds, so "untouched" is a relation */
        raw_len = EVP_PKEY_get1_encoded_public_key(np, &enc_out);
        sayn("enc.get1_unpublished_len", (long long) raw_len);
        sayn("enc.get1_unpublished_untouched", enc_out == enc_in ? 1 : 0);
        g_pn_no_encpub = 0;

        sayr("enc.set1_null_key", EVP_PKEY_set1_encoded_public_key(NULL, enc_in, sizeof enc_in));
        sayr("enc.set1_blank_key", EVP_PKEY_set1_encoded_public_key(nblank, enc_in, sizeof enc_in));
        enc_out = NULL;
        sayn("enc.get1_null_key", (long long) EVP_PKEY_get1_encoded_public_key(NULL, &enc_out));
        enc_out = NULL;
        sayn("enc.get1_blank_key", (long long) EVP_PKEY_get1_encoded_public_key(nblank, &enc_out));

        /*
         * ---- 14. `EVP_PKEY_get_group_name` ----
         */
        grp[0] = '\0';
        sayr("group.null_key", EVP_PKEY_get_group_name(NULL, grp, sizeof grp, &grp_len));
        grp[0] = '\0';
        sayr("group.blank_key", EVP_PKEY_get_group_name(nblank, grp, sizeof grp, &grp_len));
        g_pn_group = NULL;
        grp[0] = '\0';
        grp_len = 0;
        sayr("group.unpublished", EVP_PKEY_get_group_name(np, grp, sizeof grp, &grp_len));
        sayn("group.unpublished_len", (long long) grp_len);
        g_pn_group = "COURT-GROUP";
        grp[0] = '\0';
        grp_len = 0;
        sayr("group.published", EVP_PKEY_get_group_name(np, grp, sizeof grp, &grp_len));
        sayn("group.published_match", strcmp(grp, "COURT-GROUP") == 0);
        sayn("group.published_len", (long long) grp_len);
        g_pn_group = NULL;

        /*
         * ---- 15. the two type setters, on the two inputs they agree about ----
         *
         * `EVP_PKEY_set_type(nblank, EVP_PKEY_RSA)` is the third input and it is **not** here: the
         * authority finds `ossl_rsa_asn1_meth` and answers 1, this crate answers 0, and that is
         * `D-PKEY-AMETH-1` reached through a public door rather than a behaviour under test.
         */
        sayr("settype.pseudo_nid", EVP_PKEY_set_type(nblank, EVP_PKEY_KEYMGMT));
        sayr("settype.none", EVP_PKEY_set_type(nblank, EVP_PKEY_NONE));
        sayr("settype_str.measured", EVP_PKEY_set_type_str(nblank, "COURT-PKEY", 10));
        sayr("settype_str.measured_lower", EVP_PKEY_set_type_str(nblank, "court-pkey", 10));
        sayr("settype_str.whole_name", EVP_PKEY_set_type_str(nblank, "COURT-PKEY", -1));

        /*
         * ---- 16. `EVP_PKEY_get_default_digest_name` / `_nid` ----
         *
         * The provider's `default-digest` names a **digest the provider publishes**, so the two
         * halves of `legacy_asn1_ctrl_to_param` are both reachable: the name comes back, and the
         * fetch registers it in the namemap so the name can be mapped back to an object NID.
         */
        g_pn_default_digest = NULL;
        g_pn_mandatory_digest = NULL;
        grp[0] = '\0';
        sayr("deflt.none.name", EVP_PKEY_get_default_digest_name(np, grp, sizeof grp));
        nid = -7;
        sayr("deflt.none.nid", EVP_PKEY_get_default_digest_nid(np, &nid));
        sayn("deflt.none.nid_out", nid);
        sayr("deflt.none.null_key", EVP_PKEY_get_default_digest_nid(NULL, &nid));

        g_pn_default_digest = "SHA256";
        grp[0] = '\0';
        sayr("deflt.default.name", EVP_PKEY_get_default_digest_name(np, grp, sizeof grp));
        sayn("deflt.default.match", strcmp(grp, "SHA256") == 0);
        nid = -7;
        sayr("deflt.default.nid", EVP_PKEY_get_default_digest_nid(np, &nid));
        sayn("deflt.default.nid_out", nid);

        g_pn_mandatory_digest = "SHA256";
        grp[0] = '\0';
        sayr("deflt.mandatory.name", EVP_PKEY_get_default_digest_name(np, grp, sizeof grp));
        sayn("deflt.mandatory.match", strcmp(grp, "SHA256") == 0);
        g_pn_default_digest = NULL;
        g_pn_mandatory_digest = NULL;

        /*
         * ---- 17. the raw key pair, exported back from the bytes it was built from ----
         */
        rk_params[0] = OSSL_PARAM_construct_octet_string("priv", raw_priv, sizeof raw_priv);
        rk_params[1] = OSSL_PARAM_construct_octet_string("pub", raw_pub, sizeof raw_pub);
        rk_params[2] = OSSL_PARAM_construct_end();
        sayr("raw.fromdata_init", EVP_PKEY_fromdata_init(nctx));
        sayr("raw.fromdata", EVP_PKEY_fromdata(nctx, &rk, EVP_PKEY_KEYPAIR, rk_params));
        sayp("raw.key", rk);
        raw_len = sizeof raw_out;
        sayr("raw.priv", EVP_PKEY_get_raw_private_key(rk, raw_out, &raw_len));
        sayn("raw.priv_len", (long long) raw_len);
        sayn("raw.priv_match", memcmp(raw_out, raw_priv, sizeof raw_priv) == 0);
        raw_len = sizeof raw_out;
        sayr("raw.pub", EVP_PKEY_get_raw_public_key(rk, raw_out, &raw_len));
        sayn("raw.pub_len", (long long) raw_len);
        sayn("raw.pub_match", memcmp(raw_out, raw_pub, sizeof raw_pub) == 0);
        raw_len = sizeof raw_out;
        sayr("raw.priv_length_query", EVP_PKEY_get_raw_private_key(rk, NULL, &raw_len));
        sayn("raw.priv_length_query_len", (long long) raw_len);
        raw_len = sizeof raw_out;
        sayr("raw.no_export_callback", EVP_PKEY_get_raw_private_key(pkey, raw_out, &raw_len));

        /*
         * ---- 18. `EVP_PKEY_new_CMAC_key` ----
         *
         * Only the first refusal is drivable: `cipher_name == NULL` is the same statement on both
         * sides, while the arm that gets past it needs the **default** library context's CMAC
         * keymgmt, and this crate has no default provider (Phase 9). See the block below.
         */
        {
            unsigned char cmac_in[4] = { 9, 8, 7, 6 };

            sayp("cmac.no_cipher_name",
                 EVP_PKEY_new_CMAC_key(NULL, cmac_in, sizeof cmac_in, NULL));
        }

        /*
         * ---- 19. `EVP_PKEY_Q_keygen`, one arm per name the walk reads ----
         *
         * The three names are the whole of the `va_arg` walk: `"EC"` reads a `char *`, `"RSA"` a
         * `size_t`, and `"COURT-GEN"` **nothing at all** -- which is the arm a transcription that
         * ended its `if`/`else` chain with an `else` would fail, because the provider would then
         * see a parameter the caller never passed.
         */
        reset_gen();
        qk = EVP_PKEY_Q_keygen(ctx, NULL, "EC", (char *) "COURT-GROUP");
        sayp("qkeygen.ec", qk);
        say_gen("qkeygen.ec.vec");
        sayn("qkeygen.ec.group_match", strcmp(g_gen_group, "COURT-GROUP") == 0);
        EVP_PKEY_free(qk);

        reset_gen();
        qk = EVP_PKEY_Q_keygen(ctx, NULL, "ec", (char *) "LOWER-CASE");
        sayp("qkeygen.ec_lower", qk);
        sayn("qkeygen.ec_lower.group_match", strcmp(g_gen_group, "LOWER-CASE") == 0);
        EVP_PKEY_free(qk);

        reset_gen();
        qk = EVP_PKEY_Q_keygen(ctx, NULL, "RSA", (size_t) 512);
        sayp("qkeygen.rsa", qk);
        say_gen("qkeygen.rsa.vec");
        EVP_PKEY_free(qk);

        reset_gen();
        qk = EVP_PKEY_Q_keygen(ctx, NULL, "COURT-GEN");
        sayp("qkeygen.other", qk);
        say_gen("qkeygen.other.vec");
        EVP_PKEY_free(qk);

        sayp("qkeygen.no_such_type", EVP_PKEY_Q_keygen(ctx, NULL, "NO-SUCH-TYPE"));

        /*
         * ---- 20. `EVP_PKEY_CTX_set_group_name` / `_get_group_name` ----
         *
         * The refusal is about the **operation bit**, not about the key: a context with no method
         * at all is refused for the same reason a signature context is, and the `-1` an absent
         * name gets sits between the refusal and the delegation.
         */
        sayr("ctxgrp.set_on_non_gen", EVP_PKEY_CTX_set_group_name(nctx, "P-256"));
        grp[0] = '\0';
        sayr("ctxgrp.get_on_non_gen", EVP_PKEY_CTX_get_group_name(nctx, grp, sizeof grp));
        sayr("ctxgrp.set_null_ctx", EVP_PKEY_CTX_set_group_name(NULL, "P-256"));
        grp[0] = '\0';
        sayr("ctxgrp.get_null_ctx", EVP_PKEY_CTX_get_group_name(NULL, grp, sizeof grp));

        reset_gen();
        sayr("ctxgrp.keygen_init", EVP_PKEY_keygen_init(ngctx));
        say_gen("ctxgrp.keygen_init.vec");
        sayr("ctxgrp.set_on_gen", EVP_PKEY_CTX_set_group_name(ngctx, "COURT-GROUP"));
        sayn("ctxgrp.gen_saw_group", strcmp(g_gen_group, "COURT-GROUP") == 0);
        sayr("ctxgrp.set_null_name", EVP_PKEY_CTX_set_group_name(ngctx, NULL));
        grp[0] = '\0';
        sayr("ctxgrp.get_on_gen", EVP_PKEY_CTX_get_group_name(ngctx, grp, sizeof grp));
        sayn("ctxgrp.get_match", strcmp(grp, "COURT-GROUP") == 0);
        grp[0] = '\0';
        sayr("ctxgrp.get_null_name", EVP_PKEY_CTX_get_group_name(ngctx, NULL, 0));
        say_gen("ctxgrp.vec");

        /*
         * ---- 21. `EVP_PKEY_CTX_set_signature` ----
         *
         * The parameter reaches the **provider** and nothing else happens: the context's method is
         * not replaced, which is why the arm arms the context first and reads the counter after.
         * `SIG-SetParams` exists only so that a `set_ctx_params` is there to receive it.
         */
        ssig = EVP_SIGNATURE_fetch(ctx, "SIG-SetParams", NULL);
        sayp("ctxsig.algo", ssig);
        g_qon = "QON-SSP";
        sayr("ctxsig.sign_init_ex2", EVP_PKEY_sign_init_ex2(sctx, ssig, NULL));
        reset_ssp();
        sayr("ctxsig.set_signature", EVP_PKEY_CTX_set_signature(sctx, sig_in, sizeof sig_in));
        sayn("ctxsig.calls", ssp_calls);
        sayn("ctxsig.saw_signature", ssp_saw);
        sayn("ctxsig.len", ssp_len);
        sayn("ctxsig.match", memcmp(ssp_bytes, sig_in, sizeof sig_in) == 0);
        sayr("ctxsig.null_ctx", EVP_PKEY_CTX_set_signature(NULL, sig_in, sizeof sig_in));
        EVP_SIGNATURE_free(ssig);
        g_qon = "COURT-SIG";

        /*
         * ---- 22. `EVP_PKEY_CTX_set_algor_params` / `_get_algor_params`, as a round trip ----
         *
         * The caller's `X509_ALGOR` is a stack object with the header's own two fields; the value
         * it carries is an `ASN1_TYPE` holding a UTF-8 string, and the comparison afterwards is
         * against those three bytes rather than against the DER, so a transcription that encoded
         * or decoded the wrong wrapper is visible.
         */
        memset(&alg_str, 0, sizeof alg_str);
        alg_str.length = 3;
        alg_str.type = V_ASN1_UTF8STRING;
        alg_str.data = (unsigned char *) "abc";
        memset(&alg_type, 0, sizeof alg_type);
        alg_type.type = V_ASN1_UTF8STRING;
        alg_type.value.asn1_string = &alg_str;
        alg_in.algorithm = NULL;
        alg_in.parameter = &alg_type;

        reset_gen();
        sayr("algor.set", EVP_PKEY_CTX_set_algor_params(ngctx, &alg_in));
        say_gen("algor.set.vec");
        alg_out.algorithm = NULL;
        alg_out.parameter = NULL;
        sayr("algor.get", EVP_PKEY_CTX_get_algor_params(ngctx, &alg_out));
        sayp("algor.get.parameter", alg_out.parameter);
        sayn("algor.get.type", alg_out.parameter != NULL ? alg_out.parameter->type : -1);
        sayn("algor.get.match",
             alg_out.parameter != NULL
             && alg_out.parameter->value.asn1_string != NULL
             && alg_out.parameter->value.asn1_string->length == 3
             && memcmp(alg_out.parameter->value.asn1_string->data, "abc", 3) == 0);
        ASN1_TYPE_free(alg_out.parameter);
        alg_out.parameter = NULL;

        /* A provider that answers nothing: `ret` stays -1 and `alg->parameter` is untouched. */
        g_gen_aid_len = 0;
        sayr("algor.get_unpublished", EVP_PKEY_CTX_get_algor_params(ngctx, &alg_out));
        sayp("algor.get_unpublished.parameter", alg_out.parameter);

        /* `i2d_ASN1_TYPE(NULL, &der)` writes nothing, so a NULL parameter is sent as zero bytes
         * rather than refused. */
        alg_in.parameter = NULL;
        reset_gen();
        sayr("algor.set_null_parameter", EVP_PKEY_CTX_set_algor_params(ngctx, &alg_in));
        say_gen("algor.set_null_parameter.vec");
        alg_in.parameter = &alg_type;

        /*
         * ---- 23. the four raw-key constructors ----
         *
         * Each is driven once through `_ex` (an explicit context and an explicit name) and once
         * through the legacy-type spelling (no context, and the name comes from `OBJ_nid2sn`), and
         * each successful construction is followed by the **round trip**: the bytes come back out
         * through `EVP_PKEY_get_raw_private_key`/`_public_key` and are compared against the
         * probe's own input. `EVP_PKEY_X448` is the arm that proves the engine block's
         * `tmpe == NULL -> ameth = NULL`: the authority's `EVP_PKEY_asn1_find` *finds*
         * `ossl_ecx448_asn1_meth` for 1035, and the provider branch is still the one taken.
         * `EVP_PKEY_NONE` is the third: its name is `OBJ_nid2sn(0)`, `"UNDEF"`, which nothing but
         * this probe publishes.
         */
        {
            unsigned char raw_in[4] = { 'r', 'a', 'w', 'k' };
            unsigned char raw_pub[4] = { 'p', 'u', 'b', 'k' };
            unsigned char back[8];
            size_t back_len;
            EVP_PKEY *raw;

            reset_pn();
            raw = EVP_PKEY_new_raw_private_key_ex(ctx, "COURT-RAWKEY", NULL, raw_in,
                                                  sizeof raw_in);
            sayp("rawkey.ex.priv", raw);
            say_pn("rawkey.ex.priv.vec");
            back_len = sizeof back;
            sayr("rawkey.ex.priv.get", EVP_PKEY_get_raw_private_key(raw, back, &back_len));
            sayn("rawkey.ex.priv.len", (long long) back_len);
            sayn("rawkey.ex.priv.round_trip",
                 memcmp(back, raw_in, sizeof raw_in) == 0);
            EVP_PKEY_free(raw);

            raw = EVP_PKEY_new_raw_public_key_ex(ctx, "COURT-RAWKEY", NULL, raw_pub,
                                                 sizeof raw_pub);
            sayp("rawkey.ex.pub", raw);
            back_len = sizeof back;
            sayr("rawkey.ex.pub.get", EVP_PKEY_get_raw_public_key(raw, back, &back_len));
            sayn("rawkey.ex.pub.round_trip",
                 memcmp(back, raw_pub, sizeof raw_pub) == 0);
            EVP_PKEY_free(raw);

            /* The context the name would need does not exist: `EVP_KEYMGMT_fetch` raised. */
            sayp("rawkey.ex.no_type",
                 EVP_PKEY_new_raw_private_key_ex(ctx, "NO-SUCH-RAWTYPE", NULL, raw_in,
                                                 sizeof raw_in));

            /* A provider that refuses `import`: `EVP_PKEY_fromdata` answers != 1 and the
             * `EVP_R_KEY_SETUP_FAILED` arm is taken. */
            g_pn_import_fails = 1;
            raw = EVP_PKEY_new_raw_private_key_ex(ctx, "COURT-RAWKEY", NULL, raw_in,
                                                  sizeof raw_in);
            sayp("rawkey.ex.import_fails", raw);
            EVP_PKEY_free(raw);
            g_pn_import_fails = 0;

            /* The legacy-type spellings: `strtype` NULL, `libctx` NULL, the name is
             * `OBJ_nid2sn(type)` in the default context. */
            raw = EVP_PKEY_new_raw_private_key(EVP_PKEY_NONE, NULL, raw_in, sizeof raw_in);
            sayp("rawkey.undef.priv", raw);
            back_len = sizeof back;
            sayr("rawkey.undef.priv.get", EVP_PKEY_get_raw_private_key(raw, back, &back_len));
            sayn("rawkey.undef.priv.round_trip",
                 memcmp(back, raw_in, sizeof raw_in) == 0);
            EVP_PKEY_free(raw);

            raw = EVP_PKEY_new_raw_public_key(EVP_PKEY_NONE, NULL, raw_pub, sizeof raw_pub);
            sayp("rawkey.undef.pub", raw);
            back_len = sizeof back;
            sayr("rawkey.undef.pub.get", EVP_PKEY_get_raw_public_key(raw, back, &back_len));
            sayn("rawkey.undef.pub.round_trip",
                 memcmp(back, raw_pub, sizeof raw_pub) == 0);
            EVP_PKEY_free(raw);

            raw = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL, raw_in, sizeof raw_in);
            sayp("rawkey.x448.priv", raw);
            back_len = sizeof back;
            sayr("rawkey.x448.priv.get", EVP_PKEY_get_raw_private_key(raw, back, &back_len));
            sayn("rawkey.x448.priv.round_trip",
                 memcmp(back, raw_in, sizeof raw_in) == 0);
            EVP_PKEY_free(raw);

            raw = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, raw_pub, sizeof raw_pub);
            sayp("rawkey.x448.pub", raw);
            back_len = sizeof back;
            sayr("rawkey.x448.pub.get", EVP_PKEY_get_raw_public_key(raw, back, &back_len));
            sayn("rawkey.x448.pub.round_trip",
                 memcmp(back, raw_pub, sizeof raw_pub) == 0);
            EVP_PKEY_free(raw);
        }

        /*
         * ---- 24. `EVP_PKEY_new_CMAC_key` with a cipher ----
         *
         * The arm the first run of this slice could not drive: it resolves `"CMAC"` in the
         * **default** context, and this probe now publishes a `CMAC` key type there. The cipher is
         * `EVP_enc_null`, whose name is `"NULL"` -- which no provisioned cipher answers, and the
         * probe's import ignores it, so the round trip is against the probe's own four bytes.
         */
        {
            unsigned char cmac_in[4] = { 'c', 'm', 'a', 'c' };
            unsigned char back[8];
            size_t back_len;
            EVP_PKEY *ck;

            reset_pn();
            ck = EVP_PKEY_new_CMAC_key(NULL, cmac_in, sizeof cmac_in, EVP_enc_null());
            sayp("cmac.with_cipher", ck);
            say_pn("cmac.with_cipher.vec");
            back_len = sizeof back;
            sayr("cmac.with_cipher.get", EVP_PKEY_get_raw_private_key(ck, back, &back_len));
            sayn("cmac.with_cipher.round_trip",
                 memcmp(back, cmac_in, sizeof cmac_in) == 0);
            EVP_PKEY_free(ck);
        }

        EVP_PKEY_CTX_free(ngctx);
        EVP_PKEY_free(np);
        EVP_PKEY_free(np_silent);
        EVP_PKEY_free(np_fail);
        EVP_PKEY_free(rk);
        EVP_PKEY_free(nblank);
        EVP_PKEY_free(ntarget);
        EVP_PKEY_free(nparam);
        reset_pn();
        EVP_PKEY_CTX_free(nctx);
        say_pn("pkey.release.vec");

        /*
         * Named refusals, with the authority file and line, for the exports and the arms this
         * probe cannot drive. Each is a *statement about a boundary* rather than a silent omission.
         */
        printf("digestsign_supports_digest=NOT_MEASURED_OWED_TO_7_4_ITSELF_m_sigver_c_371\n");
        printf("set_type_legacy_nid=NOT_MEASURED_DIVERGENCE_D_PKEY_AMETH_1\n");
        printf("get_base_id_null_key=NOT_MEASURED_AUTHORITY_FAULTS\n");
        printf("get_default_digest_name_blank_key=NOT_MEASURED_AUTHORITY_FAULTS\n");
        printf("set_algor_params_null_ctx=NOT_MEASURED_AUTHORITY_FAULTS\n");
        printf("get_algor_params_null_ctx=NOT_MEASURED_AUTHORITY_FAULTS\n");
        printf("get_algor_params_existing_parameter=NOT_MEASURED_DECODER_OWNS_THE_SLOT\n");
        printf("print_public_family=NOT_MEASURED_NEEDS_OSSL_ENCODER_CTX_PHASE_10\n");
        printf("legacy_low_level_key_accessors=NOT_MEASURED_NEED_PHASE_8_KEY_TYPES\n");
        printf("set1_engine_and_get0_engine=NOT_MEASURED_ENGINE_IS_PHASE_13\n");
        printf("EVP_PKEY_type=NOT_MEASURED_STANDARD_METHODS_IS_PHASE_8\n");
        printf("EVP_PKEY_CTX_get_algor=NOT_MEASURED_NEEDS_d2i_X509_ALGOR_PHASE_11\n");
    }

    /*
     * ---- 7.4f: the signature half of `EVP_MD_CTX` (`m_sigver.c`) ----
     *
     * `do_sigver_init` reaches an `OSSL_OP_DIGEST` and an `OSSL_OP_SIGNATURE` at once, so this
     * block needs both: the SHA256 above, now fetchable because `dg_fns` publishes `get_params`,
     * and the `DSG-*` signature methods. Every arm's key is the same `pkey`, and the method
     * `do_sigver_init` fetches is chosen by moving the keymgmt's `query_operation_name` answer
     * (`g_qon`) -- the one lever it reads.
     *
     * The `ctx == NULL` arm of all ten exports is **not called**: `m_sigver.c` has no NULL test on
     * `ctx`, so the authority dereferences it (`m_sigver.c:53` for the four inits and the
     * `ctx->pctx` read at `:407`, `:457`, `:506`, `:676` for the six operate entry points) and
     * dies. The boundary is printed, the way D189's four stream arms are.
     */
    {
        EVP_MD_CTX *md = NULL, *md2 = NULL, *blank = NULL;
        EVP_PKEY_CTX *outp = NULL, *pre = NULL;
        EVP_MD *sha = NULL;
        OSSL_PARAM mdp[1];

        printf("dsg.null_ctx=NOT_MEASURED_AUTHORITY_DEREFERENCES_NULL_CTX_m_sigver_c_53\n");

        /*
         * The `pctx == NULL` arm of the six operate entry points, on a fresh context. The two
         * one-shots disagree about it -- `EVP_DigestSign` answers 0 with `INITIALIZATION_ERROR`
         * and `EVP_DigestVerify` answers **-1** with the same reason -- which is why both are
         * here rather than one.
         */
        blank = EVP_MD_CTX_new();
        len = sizeof out;
        sayr("dsg.null_pctx.sign_update", EVP_DigestSignUpdate(blank, msg, 1));
        sayr("dsg.null_pctx.verify_update", EVP_DigestVerifyUpdate(blank, msg, 1));
        sayr("dsg.null_pctx.sign_final", EVP_DigestSignFinal(blank, out, &len));
        sayr("dsg.null_pctx.verify_final", EVP_DigestVerifyFinal(blank, out, 1));
        sayr("dsg.null_pctx.sign", EVP_DigestSign(blank, out, &len, msg, 1));
        sayr("dsg.null_pctx.verify", EVP_DigestVerify(blank, out, 1, msg, 1));
        EVP_MD_CTX_free(blank);

        /*
         * The signing success path. `outp` is a *relation*: the context the out-parameter was
         * filled with is the one `ctx->pctx` holds, and no address is printed.
         */
        g_qon = "DSG-FULL";
        reset_dsg();
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.sign_init_ex.named",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayn("dsg.sign_init_ex.pctx_is_ctx_pctx",
             outp != NULL && outp == EVP_MD_CTX_get_pkey_ctx(md));
        say_dsg("dsg.sign_init_ex.named.vec");

        reset_dsg();
        sayr("dsg.sign_update.armed", EVP_DigestSignUpdate(md, msg, 3));
        say_dsg("dsg.sign_update.armed.vec");

        /*
         * The reuse arm: a second init with no key and no name reaches `reinitialize:` from the
         * `reinit` branch, so the digest is re-fetched from `ctx->reqdigest` and the *same* pctx
         * comes back through the out-parameter.
         */
        outp = NULL;
        sayr("dsg.sign_init_ex.reinit",
             EVP_DigestSignInit_ex(md, &outp, NULL, ctx, NULL, NULL, NULL));
        sayn("dsg.sign_init_ex.reinit_same_pctx", outp == EVP_MD_CTX_get_pkey_ctx(md));
        say_dsg("dsg.sign_init_ex.reinit.vec");

        /* The digest's own entry point, redirected to the operation that is armed. */
        reset_dsg();
        sayr("dsg.digest_update_redirects_sign", EVP_DigestUpdate(md, msg, 3));
        say_dsg("dsg.digest_update_redirects_sign.vec");

        /* `type`-override: `EVP_DigestSignInit` takes a method, and its name becomes `mdname`. */
        sha = EVP_MD_fetch(ctx, "SHA256", NULL);
        sayp("dsg.type_override.algo", sha);
        outp = NULL;
        reset_dsg();
        sayr("dsg.type_override.sign_init", EVP_DigestSignInit(md, &outp, sha, NULL, pkey));
        say_dsg("dsg.type_override.sign_init.vec");

        /*
         * The two-call convention on one context, then the buffer-too-small refusal. The first
         * call is the length query (a NULL buffer answers 8); the second runs on a duplicate and
         * leaves the context usable, which is why a third call is possible at all.
         */
        reset_dsg();
        len = 0;
        sayr("dsg.sign_final.query", EVP_DigestSignFinal(md, NULL, &len));
        sayn("dsg.sign_final.query_len", (long long) len);
        len = sizeof out;
        sayr("dsg.sign_final.value", EVP_DigestSignFinal(md, out, &len));
        sayn("dsg.sign_final.value_len", (long long) len);
        len = 4;
        sayr("dsg.sign_final.short", EVP_DigestSignFinal(md, out, &len));
        say_dsg("dsg.sign_final.vec");

        /* The one-shot `EVP_DigestSign`, and its absent-buffer arm. */
        reset_dsg();
        len = sizeof out;
        sayr("dsg.sign.oneshot", EVP_DigestSign(md, out, &len, msg, 3));
        say_dsg("dsg.sign.oneshot.vec");
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * The `digest_sign_update`/`_final` absence pair, and the one-shot fall-through: a
         * `DSG-NOSTREAM` method has a `digest_sign` but neither stream callback, so
         * `EVP_DigestSignUpdate`/`Final` are refused with `PROVIDER_SIGNATURE_NOT_SUPPORTED` while
         * `EVP_DigestSign` still succeeds through `digest_sign`.
         */
        g_qon = "DSG-NOSTREAM";
        reset_dsg();
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.nostream.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayr("dsg.nostream.sign_update", EVP_DigestSignUpdate(md, msg, 3));
        len = sizeof out;
        sayr("dsg.nostream.sign_final", EVP_DigestSignFinal(md, out, &len));
        len = sizeof out;
        sayr("dsg.nostream.sign_oneshot", EVP_DigestSign(md, out, &len, msg, 3));
        say_dsg("dsg.nostream.vec");
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * The sign-only method: its `digest_verify_init` is absent, which is `m_sigver.c:258`.
         */
        g_qon = "DSG-SIGNONLY";
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.signonly.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayr("dsg.signonly.verify_init",
             EVP_DigestVerifyInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        EVP_MD_CTX_free(md);
        md = NULL;

        /* The mirror: a verify-only method refuses `digest_sign_init` at `m_sigver.c:266`. */
        g_qon = "DSG-VERIFYONLY";
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.verifyonly.verify_init",
             EVP_DigestVerifyInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayr("dsg.verifyonly.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        EVP_MD_CTX_free(md);
        md = NULL;

        /* `newctx` answering NULL is `m_sigver.c:201`. */
        g_qon = "DSG-NONEWCTX";
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.nonewctx.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayn("dsg.nonewctx.pctx_not_filled", outp == NULL);
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * A digest name that cannot be fetched: the return code and whatever the mark/pop pair
         * leaves on the queue. The name is deliberately one nothing publishes on either side.
         */
        g_qon = "DSG-FULL";
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.bad_digest.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "COURT-NO-SUCH-DIGEST", ctx, NULL, pkey, NULL));
        /* The out-parameter *is* filled: `reinitialize:` runs `*pctx = locpctx` before the digest
         * fetch that fails. */
        sayn("dsg.bad_digest.pctx_filled", outp != NULL);
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * `mdname == NULL` on a fresh context: the keymgmt answers nothing for
         * `default-digest`, so the init is handed NULL and the operation is still armed.
         */
        reset_dsg();
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.null_mdname.sign_init",
             EVP_DigestSignInit_ex(md, &outp, NULL, ctx, NULL, pkey, NULL));
        say_dsg("dsg.null_mdname.vec");
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * `pkey == NULL`: the `EVP_PKEY_CTX` constructor inside `do_sigver_init` cannot resolve a
         * method, so the init answers 0 and the only error is the constructor's.
         */
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.null_pkey.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, NULL, NULL));
        sayn("dsg.null_pkey.pctx_not_filled", outp == NULL);
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * The legacy entry the loop reaches: the keymgmt answers a name nothing publishes, so
         * both fetch iterations fail and the label refuses with
         * `OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`.
         */
        g_qon = "COURT-NO-SUCH-SIG";
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.legacy.no_such_sig",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayn("dsg.legacy.pctx_not_filled", outp == NULL);
        EVP_MD_CTX_free(md);
        md = NULL;
        g_qon = "DSG-FULL";

        /*
         * `provkey == NULL`: a key with a method and no key data cannot be exported to the
         * method's provider, so the loop falls out and `m_sigver.c:187` refuses.
         */
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.empty_key.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, empty, NULL));
        sayn("dsg.empty_key.pctx_not_filled", outp == NULL);
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * `NO_KEY_SET` (`m_sigver.c:87`): a context whose pctx is a method with no key. The
         * caller supplies the pctx, so the caller owns it: `EVP_MD_CTX_set_pkey_ctx(md, NULL)`
         * releases it, and the KEEP_PKEY_CTX flag is what makes the reset not do so.
         */
        pre = EVP_PKEY_CTX_new_from_name(ctx, "COURT-SIGKEY", NULL);
        sayp("dsg.nokey.pre_ctx", pre);
        md = EVP_MD_CTX_new();
        EVP_MD_CTX_set_pkey_ctx(md, pre);
        outp = NULL;
        sayr("dsg.nokey.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, NULL, NULL));
        sayn("dsg.nokey.pctx_not_filled", outp == NULL);
        /* `KEEP_PKEY_CTX` means the reset neither releases it nor is released by this detach. */
        EVP_MD_CTX_set_pkey_ctx(md, NULL);
        EVP_PKEY_CTX_free(pre);
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * The verification arms. `EVP_DigestVerifyFinal` runs on a duplicate even without a
         * buffer convention, and `EVP_DigestVerify` marks the context finalised unconditionally,
         * which is why each success is followed by a fresh init.
         */
        g_qon = "DSG-FULL";
        reset_dsg();
        md2 = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.verify_init_ex.named",
             EVP_DigestVerifyInit_ex(md2, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayn("dsg.verify_init_ex.pctx_is_ctx_pctx",
             outp != NULL && outp == EVP_MD_CTX_get_pkey_ctx(md2));
        sayr("dsg.verify_update.armed", EVP_DigestVerifyUpdate(md2, msg, 3));
        sayr("dsg.verify_final.good", EVP_DigestVerifyFinal(md2, out, 8));
        sayr("dsg.verify_final.short", EVP_DigestVerifyFinal(md2, out, 4));
        say_dsg("dsg.verify_final.vec");
        EVP_MD_CTX_free(md2);
        md2 = NULL;

        reset_dsg();
        md2 = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.verify.oneshot_init",
             EVP_DigestVerifyInit_ex(md2, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayr("dsg.verify.oneshot", EVP_DigestVerify(md2, out, 8, msg, 3));
        sayr("dsg.verify.oneshot_again", EVP_DigestVerify(md2, out, 8, msg, 3));
        say_dsg("dsg.verify.oneshot.vec");
        EVP_MD_CTX_free(md2);
        md2 = NULL;

        /* `EVP_DigestVerify` with no `digest_verify`: update then final. */
        g_qon = "DSG-NOSTREAM";
        reset_dsg();
        md2 = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.nostream.verify_init",
             EVP_DigestVerifyInit_ex(md2, &outp, "SHA256", ctx, NULL, pkey, NULL));
        sayr("dsg.nostream.verify_update", EVP_DigestVerifyUpdate(md2, msg, 3));
        sayr("dsg.nostream.verify_final", EVP_DigestVerifyFinal(md2, out, 8));
        say_dsg("dsg.nostream.verify.vec");
        EVP_MD_CTX_free(md2);
        md2 = NULL;

        /*
         * The no-`dupctx` method: a final with a buffer cannot duplicate, so it runs on the
         * original and marks the context, and the next final is `FINAL_ERROR`.
         */
        g_qon = "DSG-NODUP";
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.nodup.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        len = sizeof out;
        sayr("dsg.nodup.sign_final", EVP_DigestSignFinal(md, out, &len));
        len = sizeof out;
        sayr("dsg.nodup.sign_final_again", EVP_DigestSignFinal(md, out, &len));
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * The `digest_sign_init` that answers 0 with no digest name: `NO_DEFAULT_DIGEST` first,
         * then `PROVIDER_SIGNATURE_FAILURE`, and the context is *not* left armed -- this is the
         * `err:` label. With a name the same callback's 0 is a success, which is the other half.
         */
        g_qon = "DSG-FULL";
        g_dsg_init_fails = 1;
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.init_fails.null_mdname",
             EVP_DigestSignInit_ex(md, &outp, NULL, ctx, NULL, pkey, NULL));
        EVP_MD_CTX_free(md);
        md = NULL;
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.init_fails.named",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        EVP_MD_CTX_free(md);
        md = NULL;
        g_dsg_init_fails = 0;

        /*
         * The md-parameter redirect: a signature method that publishes the md-parameter pair is
         * preferred by `EVP_MD_CTX_set_params`/`_settable_params` over the digest's own.
         */
        g_qon = "DSG-SETMD";
        md = EVP_MD_CTX_new();
        outp = NULL;
        sayr("dsg.setmd.sign_init",
             EVP_DigestSignInit_ex(md, &outp, "SHA256", ctx, NULL, pkey, NULL));
        n_setmd = 0;
        mdp[0] = OSSL_PARAM_construct_end();
        sayr("dsg.setmd.mdctx_set_params", EVP_MD_CTX_set_params(md, mdp));
        sayn("dsg.setmd.set_redirected", n_setmd);
        sayp("dsg.setmd.mdctx_settable_params", (const void *) EVP_MD_CTX_settable_params(md));
        sayn("dsg.setmd.get_redirected", n_getmd);
        sayr("dsg.setmd.mdctx_get_params", EVP_MD_CTX_get_params(md, mdp));
        sayn("dsg.setmd.get_redirected_after", n_getmd);
        sayp("dsg.setmd.mdctx_gettable_params", (const void *) EVP_MD_CTX_gettable_params(md));
        EVP_MD_CTX_free(md);
        md = NULL;

        /*
         * `EVP_PKEY_digestsign_supports_digest` (`p_lib.c:1398`). Its whole answer is the return
         * code: the outer `ERR_set_mark`/`ERR_pop_to_mark` removes everything the init raised, so
         * the `err=` on these lines is the *empty* queue a refused name leaves. The `-1` arm is
         * the `EVP_MD_CTX_new` failure, which has no injectable seam and is named rather than
         * faked.
         */
        g_qon = "DSG-FULL";
        reset_dsg();
        sayr("dsg.supports.named",
             EVP_PKEY_digestsign_supports_digest(pkey, ctx, "SHA256", NULL));
        sayr("dsg.supports.bad_name",
             EVP_PKEY_digestsign_supports_digest(pkey, ctx, "COURT-NO-SUCH-DIGEST", NULL));
        sayr("dsg.supports.null_key",
             EVP_PKEY_digestsign_supports_digest(NULL, ctx, "SHA256", NULL));
        say_dsg("dsg.supports.vec");
        printf("dsg.supports.new_ctx_fails=NOT_MEASURED_NO_INJECTABLE_ALLOC_SEAM_p_lib_c_1404\n");

        EVP_MD_free(sha);
        g_qon = "COURT-SIG";
    }

    /*
     * ---- release ----
     *
     * `EVP_KEYMGMT_free` releases the *method*. Neither the signature method's `freectx` nor the
     * keymgmt's `free` is its business: the first belongs to the operation context, the second to
     * the key data, and `EVP_PKEY_free` is what reaches it.
     */
    reset_c();
    again = EVP_KEYMGMT_fetch(ctx, "COURT-SIGKEY", NULL);
    sayn("release.keymgmt_same_object", again == keymgmt ? 1 : 0);
    EVP_KEYMGMT_free(again);
    say_k("release.vec.before");
    EVP_PKEY_free(empty);
    say_k("release.vec.after_empty_pkey");
    EVP_PKEY_free(pkey);
    say_k("release.vec.after_pkey");
    EVP_PKEY_CTX_free(fctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(ectx);
    EVP_KEYMGMT_free(keymgmt);
    say_k("release.vec.after_all");
    sayn("unload", OSSL_PROVIDER_unload(prov));
    /* The default-context provider goes last: nothing after it may fetch. */
    sayn("unload_default", OSSL_PROVIDER_unload(prov_default));
    OSSL_LIB_CTX_free(ctx);
    printf("done=1\n");
    return 0;
}
