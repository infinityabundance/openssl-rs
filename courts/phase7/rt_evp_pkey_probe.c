/*
 * RT-EVP-PKEY -- `crypto/evp/signature.c`'s entry-point half, differentially.
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
 *   * **`EVP_PKEY_CTX_set_signature`.** It is `pmeth_lib.c`'s and another slice's.
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

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

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

/* ------------------------------------------------------------------ the two bodies of algorithms */

#define COURT_PROV "provider=court-pkey"

static const OSSL_ALGORITHM court_keymgmts[] = {
    { "COURT-SIGKEY:courtsigkey", COURT_PROV, kmgm_fns,
      "the probe's key type, and the one the key's preferred-signature name comes from" },
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
    OSSL_PROVIDER *prov;
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
    OSSL_LIB_CTX_free(ctx);
    printf("done=1\n");
    return 0;
}
