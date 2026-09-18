/*
 * RT-EVP-RAND -- the `EVP_RAND` method object and the context it is run through.
 *
 * The third provider-only class, and the one that breaks the pattern `RT-EVP-MAC` and `RT-EVP-KDF`
 * established. Five things are observable here that neither of those courts could observe, and each
 * one is a place where a plausible transcription is wrong:
 *
 *   1. **the constructor has three arguments, and the third is a dispatch table.** `newctx` is
 *      handed `(provctx, parent_algctx, parent_dispatch)`. The probe pins all three relations: with
 *      no parent both are NULL, with a parent the second is the parent's *algorithm* context (a
 *      pointer this probe holds, because it is this probe's own provider that allocated it) and the
 *      third is a table whose first id is the parent's first id and whose entry count is the
 *      parent's entry count. That is the whole mechanism by which a provider DRBG chains onto
 *      another one's, and "the child was handed the parent's EVP_RAND object" is a wrong answer
 *      that only this observation distinguishes.
 *   2. **a context is reference counted and its release is recursive.** `EVP_RAND_CTX_new` takes a
 *      reference on the parent context; `EVP_RAND_CTX_free` on the last reference releases the
 *      method, the algorithm context, and *then* the parent. So the same call is a no-op and a
 *      release depending only on how many references are outstanding, and the vector of the
 *      provider's `freectx` count across a chain of calls is the observation. A one-level
 *      transcription frees the child and leaks every ancestor.
 *   3. **every operation is wrapped in the provider's lock, and the lock is optional.** A method
 *      with no `lock` answers 1 for every acquisition; the lock and unlock counters are therefore
 *      zero on the plain method and non-zero on the locked one, for the *same* call.
 *   4. **the locking counters are independent of each other.** The structural check is
 *      `fnenablelockcnt in {0,1}` *and* `fnlockcnt in {0,2}` -- two separate conditions -- so
 *      `enable_locking` without `lock` is **fetchable**, where `lock` without `unlock` is not. A
 *      transcription that folded the two into one counter would refuse one of them and there is
 *      nothing else in the API that would notice.
 *   5. **`generate` is chunked by a parameter the method itself reports**, and the loop is
 *      `for (; outlen > 0; outlen -= chunk, out += chunk)`. So a generation of twenty bytes over a
 *      `max_request` of seven is three callback calls with lengths 7, 7, 6; the advanced `out` is
 *      visible in *which bytes changed*; `prediction_resistance` is cleared after the first call;
 *      an `outlen` of zero is a success with no callback at all; and a `max_request` of zero is a
 *      refusal raised before the loop. All four are pinned below.
 *
 * The eighteen dispatch ids are the wire format, so they are what a provider is compiled against;
 * the probe publishes twelve algorithms so that the *fetch-time* structural check is observed from
 * both sides rather than trusted: eight are constructed and four are refused, and the four
 * refusals are the four counters (no `generate`, no `get_ctx_params`, no `freectx`, `lock` without
 * `unlock`).
 *
 * Deliberately not observed
 * -------------------------
 *   * **`evp_rand_can_seed`, `evp_rand_get_seed` and `evp_rand_clear_seed`**, which are internal,
 *     are declared in `include/crypto/evp.h` (not installed) and are called only by
 *     `crypto/rand/rand_lib.c` -- Phase 9's. The `get_seed`/`clear_seed` dispatch ids are still
 *     *reachable* through the walk, but a provider cannot publish a callback whose signature names
 *     `EVP_RAND_CTX`, and the probe has no caller.
 *   * **`EVP_RAND_do_all_provided` with a NULL visitor**, which faults the authority
 *     (`docs/SECURITY_DIVERGENCE_POLICY.md` D-MD-DOALL-NULL-1). The boundary is printed.
 *   * **`EVP_RAND_get0_name` and its siblings on a NULL method**, which dereference. The
 *     reference-counted entry points are the ones with NULL guards, and those are observed:
 *     `EVP_RAND_up_ref(NULL)` answers 1 because the authority's static helper checks, and
 *     `EVP_RAND_CTX_free(NULL)` returns. Both are measured, because "a NULL is refused" and "a
 *     NULL is a no-op" are different contracts and this class has one of each.
 *
 * Addresses are never printed. Every observation is a relation between two pointers this probe
 * holds, a presence answer, a count, a packed argument vector or a return code.
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

#define COURT_GEN_OUT 64

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull", ERR_peek_error());
    ERR_clear_error();
}

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

/* ---- the provider's own RAND, and the counters that are the observation ---- */

enum court_flavor {
    F_BASE,        /* the complete method and nothing more */
    F_FULL,        /* base + reseed, nonce, get_params, enable_locking, lock, unlock */
    F_NOVERIFY,    /* base without verify_zeroization */
    F_ENABLEONLY,  /* base + enable_locking, and **no** lock pair */
    F_CHILD,       /* base, whose constructor records what it was handed */
    F_SMALLMAX,    /* base, whose max_request is 7 */
    F_ZEROMAX,     /* base, whose max_request is 0 */
    F_BADPARAMS    /* base, whose get_ctx_params refuses */
};

struct court_rand_st {
    int flavor;
    unsigned int strength;
    int state;
    unsigned long fold;
};

/* Fourteen counters, printed as one vector: which callback ran and how many times. */
static int c_new, c_free, c_inst, c_uninst, c_gen, c_reseed, c_nonce;
static int c_getp, c_setp, c_lock, c_unlock, c_enable, c_verify, c_getprm;

/* The argument observations, all reset by `reset_obs`. */
static unsigned long c_chunks;      /* the generate call lengths, base 256 */
static int c_chunk_n;               /* how many generate calls */
static unsigned long c_pred;        /* one bit per generate call, MSB = first call */
static unsigned long c_inst_args;   /* (strength << 12) | (prediction_resistance << 1) | pstr_seen */
static unsigned long c_reseed_args; /* (ent_len << 12) | (addin_len << 1) | prediction_resistance */
static unsigned long c_nonce_args;  /* (strength << 12) | (outlen << 1) | (outlen2 == outlen) */

/* The parent hand-off, as relations and counts -- never an address. */
static int c_parent_was_null;      /* how many constructors were handed a NULL parent */
static int c_parent_was_algctx;    /* ...the *algorithm* context of the previous method */
static int c_parent_was_ctxstruct; /* ...some other pointer (must stay 0) */
static int c_dispatch_was_null;
static int c_dispatch_entries;
static int c_dispatch_first_id;
static int c_dispatch_same_as_before; /* second child saw the identical table pointer */

static void reset_counts(void)
{
    c_new = c_free = c_inst = c_uninst = c_gen = c_reseed = c_nonce = 0;
    c_getp = c_setp = c_lock = c_unlock = c_enable = c_verify = c_getprm = 0;
}

static void reset_obs(void)
{
    c_chunks = 0;
    c_chunk_n = 0;
    c_pred = 0;
    c_inst_args = 0;
    c_reseed_args = 0;
    c_nonce_args = 0;
}

static void say_vec(const char *key)
{
    printf("%s=%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d err=%lu\n", key,
           c_new, c_free, c_inst, c_uninst, c_gen, c_reseed, c_nonce,
           c_getp, c_setp, c_lock, c_unlock, c_enable, c_verify, c_getprm,
           ERR_peek_error());
    ERR_clear_error();
}

static void say_obs(const char *key)
{
    printf("%s=chunks:%lu n:%d pred:0x%lx inst:%lu reseed:%lu nonce:%lu err=%lu\n", key,
           c_chunks, c_chunk_n, c_pred, c_inst_args, c_reseed_args, c_nonce_args,
           ERR_peek_error());
    ERR_clear_error();
}

/* The last algorithm context this provider allocated. The child's constructor compares what it was
 * handed against it, which is how "the algorithm context, not the EVP_RAND_CTX" is observed without
 * printing either. */
static void *g_last_algctx;
static const OSSL_DISPATCH *g_last_dispatch;

static void *rnd_newctx_flavor(void *provctx, void *parent,
                               const OSSL_DISPATCH *parent_calls, int flavor)
{
    struct court_rand_st *d;
    const OSSL_DISPATCH *p;
    int entries = 0;

    (void) provctx;
    c_new++;
    if (flavor == F_CHILD) {
        if (parent == NULL)
            c_parent_was_null++;
        else if (parent == g_last_algctx)
            c_parent_was_algctx++;
        else
            c_parent_was_ctxstruct++;
        if (parent_calls == NULL) {
            c_dispatch_was_null++;
        } else {
            if (parent_calls == g_last_dispatch)
                c_dispatch_same_as_before++;
            for (p = parent_calls; p->function_id != 0; p++)
                entries++;
            c_dispatch_entries = entries;
            c_dispatch_first_id = (int) parent_calls[0].function_id;
            g_last_dispatch = parent_calls;
        }
    }
    d = malloc(sizeof *d);
    if (d == NULL)
        return NULL;
    memset(d, 0, sizeof *d);
    d->flavor = flavor;
    d->strength = 128;
    d->state = EVP_RAND_STATE_READY;
    g_last_algctx = d;
    return d;
}

static void *rnd_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    return rnd_newctx_flavor(provctx, parent, parent_calls, F_BASE);
}

static void *rnd_newctx_full(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    return rnd_newctx_flavor(provctx, parent, parent_calls, F_FULL);
}

static void *rnd_newctx_noverify(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    return rnd_newctx_flavor(provctx, parent, parent_calls, F_NOVERIFY);
}

static void *rnd_newctx_enableonly(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    return rnd_newctx_flavor(provctx, parent, parent_calls, F_ENABLEONLY);
}

static void *rnd_newctx_child(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    return rnd_newctx_flavor(provctx, parent, parent_calls, F_CHILD);
}

static void *rnd_newctx_smallmax(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    return rnd_newctx_flavor(provctx, parent, parent_calls, F_SMALLMAX);
}

static void *rnd_newctx_zeromax(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    return rnd_newctx_flavor(provctx, parent, parent_calls, F_ZEROMAX);
}

static void *rnd_newctx_badparams(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    return rnd_newctx_flavor(provctx, parent, parent_calls, F_BADPARAMS);
}

static void rnd_freectx(void *vctx)
{
    c_free++;
    free(vctx);
}

static int rnd_instantiate(void *vctx, unsigned int strength, int prediction_resistance,
                           const unsigned char *pstr, size_t pstr_len,
                           const OSSL_PARAM params[])
{
    struct court_rand_st *d = vctx;
    size_t i;

    c_inst++;
    c_inst_args = ((unsigned long) (strength & 0xfff) << 12)
                  | ((unsigned long) (prediction_resistance & 1) << 1)
                  | (pstr != NULL && pstr_len > 0 ? 1UL : 0UL);
    if (d == NULL)
        return 0;
    /* The personalisation string is folded in, so "the implementation ran and saw the input" is one
     * observation rather than two. */
    if (pstr != NULL) {
        for (i = 0; i < pstr_len; i++)
            d->fold = d->fold * 131 + pstr[i];
    }
    (void) params;
    return 1;
}

static int rnd_uninstantiate(void *vctx)
{
    struct court_rand_st *d = vctx;

    c_uninst++;
    if (d == NULL)
        return 0;
    d->fold = 0;
    return 1;
}

/* The generation writes `c_gen * 32 + i`, so the transcript says *where* each chunk landed and not
 * merely how many there were: three chunks of 7, 7, 6 put 0x20 at 0, 0x40 at 7, 0x60 at 14. */
static int rnd_generate(void *vctx, unsigned char *out, size_t outlen, unsigned int strength,
                        int prediction_resistance, const unsigned char *addin, size_t addin_len)
{
    struct court_rand_st *d = vctx;
    size_t i;

    c_gen++;
    c_chunks = c_chunks * 256 + (unsigned long) (outlen & 0xff);
    c_chunk_n++;
    c_pred = (c_pred << 1) | (unsigned long) (prediction_resistance != 0 ? 1 : 0);
    if (d == NULL || out == NULL)
        return 0;
    for (i = 0; i < outlen; i++)
        out[i] = (unsigned char) ((c_gen * 32 + (int) i) & 0xff);
    (void) strength;
    (void) addin;
    (void) addin_len;
    return 1;
}

static int rnd_reseed(void *vctx, int prediction_resistance, const unsigned char *ent,
                      size_t ent_len, const unsigned char *addin, size_t addin_len)
{
    c_reseed++;
    c_reseed_args = ((unsigned long) (ent_len & 0x3ff) << 20)
                    | ((unsigned long) (addin_len & 0x3ff) << 10)
                    | (unsigned long) (prediction_resistance != 0 ? 1 : 0);
    (void) vctx;
    (void) ent;
    (void) addin;
    return 1;
}

/* The authority asks for exactly `outlen` twice: `nonce(algctx, out, str, outlen, outlen)`. The
 * two lengths are packed as one bit rather than two numbers, because they are either equal or the
 * contract is wrong. */
static int rnd_nonce(void *vctx, unsigned char *out, unsigned int strength, size_t min_len,
                     size_t max_len)
{
    size_t i;

    c_nonce++;
    c_nonce_args = ((unsigned long) (strength & 0xfff) << 12)
                   | ((unsigned long) (max_len & 0x7ff) << 1)
                   | (min_len == max_len ? 1UL : 0UL);
    if (out == NULL)
        return 0;
    for (i = 0; i < max_len; i++)
        out[i] = (unsigned char) (0xA0 + (i & 0x0f));
    (void) vctx;
    return 1;
}

static int rnd_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    size_t maxreq = 16;

    c_getprm++;
    if (p != NULL && !OSSL_PARAM_set_size_t(p, maxreq))
        return 0;
    return 1;
}

/* The refusal is the *whole method's*, not the parameter's: a method that cannot answer this
 * question is a method whose `generate` cannot run, and the fetch-time check counts `get_ctx_params`
 * among the three context functions for that reason. */
static int rnd_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct court_rand_st *d = vctx;
    OSSL_PARAM *p;
    size_t maxreq = 16;

    c_getp++;
    if (d == NULL || d->flavor == F_BADPARAMS)
        return 0;
    if (d->flavor == F_ZEROMAX)
        maxreq = 0;
    if (d->flavor == F_SMALLMAX)
        maxreq = 7;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, maxreq))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, d->strength))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, d->state))
        return 0;
    return 1;
}

static int rnd_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct court_rand_st *d = vctx;
    const OSSL_PARAM *p;

    c_setp++;
    if (d == NULL)
        return 0;
    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &d->strength))
        return 0;
    return 1;
}

static int rnd_enable_locking(void *vctx)
{
    c_enable++;
    (void) vctx;
    return 1;
}

static int rnd_lock(void *vctx)
{
    c_lock++;
    (void) vctx;
    return 1;
}

static void rnd_unlock(void *vctx)
{
    c_unlock++;
    (void) vctx;
}

static int rnd_verify_zeroization(void *vctx)
{
    const struct court_rand_st *d = vctx;

    c_verify++;
    /* A method that has never been uninstantiated still holds a fold. */
    if (d == NULL)
        return 0;
    return d->fold == 0;
}

static const OSSL_PARAM *rnd_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    (void) provctx;
    return gettable;
}

static const OSSL_PARAM *rnd_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_END
    };

    (void) vctx;
    (void) provctx;
    return gettable;
}

static const OSSL_PARAM *rnd_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_END
    };

    (void) vctx;
    (void) provctx;
    return settable;
}

/* ---- the twelve dispatch tables ---- */

static const OSSL_DISPATCH rnd_base_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void)) rnd_gettable_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) rnd_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void)) rnd_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void)) rnd_verify_zeroization },
    { 0, NULL }
};

/* Seventeen entries: the table the child is handed, and its length and first id are observed. */
static const OSSL_DISPATCH rnd_full_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx_full },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_RESEED, (void (*)(void)) rnd_reseed },
    { OSSL_FUNC_RAND_NONCE, (void (*)(void)) rnd_nonce },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void)) rnd_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void)) rnd_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void)) rnd_unlock },
    { OSSL_FUNC_RAND_GET_PARAMS, (void (*)(void)) rnd_get_params },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void)) rnd_gettable_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) rnd_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void)) rnd_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void)) rnd_verify_zeroization },
    { 0, NULL }
};

static const OSSL_DISPATCH rnd_noverify_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx_noverify },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void)) rnd_gettable_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) rnd_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void)) rnd_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { 0, NULL }
};

/* `fnenablelockcnt` is 1 and `fnlockcnt` is 0, and that is **fetchable**: the two counters are
 * independent conditions, not one. */
static const OSSL_DISPATCH rnd_enableonly_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx_enableonly },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void)) rnd_enable_locking },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void)) rnd_gettable_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) rnd_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void)) rnd_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void)) rnd_verify_zeroization },
    { 0, NULL }
};

static const OSSL_DISPATCH rnd_child_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx_child },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void)) rnd_gettable_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) rnd_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void)) rnd_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void)) rnd_verify_zeroization },
    { 0, NULL }
};

static const OSSL_DISPATCH rnd_smallmax_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx_smallmax },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void)) rnd_gettable_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) rnd_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void)) rnd_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void)) rnd_verify_zeroization },
    { 0, NULL }
};

static const OSSL_DISPATCH rnd_zeromax_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx_zeromax },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void)) rnd_gettable_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) rnd_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void)) rnd_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void)) rnd_verify_zeroization },
    { 0, NULL }
};

static const OSSL_DISPATCH rnd_badparams_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx_badparams },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void)) rnd_gettable_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) rnd_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void)) rnd_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void)) rnd_verify_zeroization },
    { 0, NULL }
};

/* No `generate`: `fnrandcnt` is 2 where the check wants exactly 3. */
static const OSSL_DISPATCH rnd_nogen_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { 0, NULL }
};

/* No `get_ctx_params`: `fnctxcnt` is 2. */
static const OSSL_DISPATCH rnd_nogetctx_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { 0, NULL }
};

/* No `freectx`: `fnctxcnt` is 2. */
static const OSSL_DISPATCH rnd_nofreectx_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { 0, NULL }
};

/* A `lock` with no `unlock`: `fnlockcnt` is 1 where the check wants 0 or 2. */
static const OSSL_DISPATCH rnd_nolockpair_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) rnd_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void)) rnd_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) rnd_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) rnd_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void)) rnd_generate },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void)) rnd_lock },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) rnd_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void)) rnd_set_ctx_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM court_rands[] = {
    { "court-rand:Court-RAND:courtrand", "provider=court", rnd_base_fns,
      "court rand, the complete minimum" },
    { "court-rand-full:Court-RAND-full:courtrandfull", "provider=court", rnd_full_fns,
      "court rand with every optional callback" },
    { "court-rand-noverify:Court-RAND-noverify:courtrandnoverify", "provider=court",
      rnd_noverify_fns, "court rand that cannot prove its zeroization" },
    { "court-rand-enableonly:Court-RAND-enableonly:courtrandenableonly", "provider=court",
      rnd_enableonly_fns, "court rand that can be asked to lock and cannot lock" },
    { "court-rand-child:Court-RAND-child:courtrandchild", "provider=court", rnd_child_fns,
      "court rand that records what it was handed as a parent" },
    { "court-rand-smallmax:Court-RAND-smallmax:courtrandsmallmax", "provider=court",
      rnd_smallmax_fns, "court rand with a max_request of seven" },
    { "court-rand-zeromax:Court-RAND-zeromax:courtrandzeromax", "provider=court",
      rnd_zeromax_fns, "court rand that reports a max_request of zero" },
    { "court-rand-badparams:Court-RAND-badparams:courtrandbadparams", "provider=court",
      rnd_badparams_fns, "court rand whose context parameters refuse" },
    { "court-rand-nogen:Court-RAND-nogen:courtrandnogen", "provider=court", rnd_nogen_fns,
      "court rand that must be refused, for its generation" },
    { "court-rand-nogetctx:Court-RAND-nogetctx:courtrandnogetctx", "provider=court",
      rnd_nogetctx_fns, "court rand that must be refused, for its context parameters" },
    { "court-rand-nofreectx:Court-RAND-nofreectx:courtrandnofreectx", "provider=court",
      rnd_nofreectx_fns, "court rand that must be refused, for its context releaser" },
    { "court-rand-nolockpair:Court-RAND-nolockpair:courtrandnolockpair", "provider=court",
      rnd_nolockpair_fns, "court rand that must be refused, for its half a lock" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_RAND)
        return court_rands;
    return NULL;
}

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_query },
    { 0, NULL }
};

static char rnd_marker;

static int court_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_dispatch;
    *provctx = &rnd_marker;
    return 1;
}

/* ---- the do_all and name visitors ---- */

struct rand_seen {
    int count;
    int saw_plain;
    int saw_refused;
};

static void rand_visitor(EVP_RAND *rand, void *arg)
{
    struct rand_seen *s = arg;
    const char *name = EVP_RAND_get0_name(rand);

    s->count++;
    if (name != NULL && strcmp(name, "court-rand") == 0)
        s->saw_plain = 1;
    if (name != NULL && strcmp(name, "court-rand-nogen") == 0)
        s->saw_refused = 1;
}

struct rand_names {
    int count;
    int saw_identity;
    int saw_alias;
};

static void rand_name_visitor(const char *name, void *arg)
{
    struct rand_names *s = arg;

    s->count++;
    if (strcmp(name, "court-rand") == 0)
        s->saw_identity = 1;
    if (strcmp(name, "courtrand") == 0)
        s->saw_alias = 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *p;
    EVP_RAND *base, *full, *noverify, *enableonly, *child_meth, *smallmax, *zeromax, *badparams;
    EVP_RAND *nogen, *nogetctx, *nofreectx, *nolockpair, *again;
    EVP_RAND_CTX *c_base, *c_full, *c_smallmax, *c_zeromax, *c_badparams;
    unsigned char out[COURT_GEN_OUT];
    unsigned char pstr[4] = { 'p', 's', 't', 'r' };
    unsigned char ent[5] = { 'e', 'n', 't', 'r', 'o' };

    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }
    sayn("add_builtin", OSSL_PROVIDER_add_builtin(ctx, "court-rand", court_provider_init));
    p = OSSL_PROVIDER_load(ctx, "court-rand");
    printf("load=%d\n", p != NULL ? 1 : 0);
    if (p == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    reset_counts();
    reset_obs();

    /*
     * ---- the structural check, from both sides ----
     *
     * Twelve algorithms are published; eight are constructed and four are refused, and the four
     * refusals are four different counters. A transcription that accepted any of them would be
     * indistinguishable from a correct one until a caller asked the method to generate, to report
     * its own parameters, to release its context, or to lock -- which is to say, until it was too
     * late to notice.
     */
    base = EVP_RAND_fetch(ctx, "court-rand", NULL);
    full = EVP_RAND_fetch(ctx, "court-rand-full", NULL);
    noverify = EVP_RAND_fetch(ctx, "court-rand-noverify", NULL);
    enableonly = EVP_RAND_fetch(ctx, "court-rand-enableonly", NULL);
    child_meth = EVP_RAND_fetch(ctx, "court-rand-child", NULL);
    smallmax = EVP_RAND_fetch(ctx, "court-rand-smallmax", NULL);
    zeromax = EVP_RAND_fetch(ctx, "court-rand-zeromax", NULL);
    badparams = EVP_RAND_fetch(ctx, "court-rand-badparams", NULL);
    sayp("fetch.plain", base);
    sayp("fetch.full", full);
    sayp("fetch.no_verify", noverify);
    /* `enable_locking` with no `lock` is fetchable: the two counters are independent conditions. */
    sayp("fetch.enable_locking_without_lock", enableonly);
    printf("fetch.enable_locking_without_lock.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    sayp("fetch.child", child_meth);
    sayp("fetch.smallmax", smallmax);
    sayp("fetch.zeromax", zeromax);
    sayp("fetch.badparams", badparams);

    nogen = EVP_RAND_fetch(ctx, "court-rand-nogen", NULL);
    sayp("fetch.no_generate", nogen);
    printf("fetch.no_generate.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    nogetctx = EVP_RAND_fetch(ctx, "court-rand-nogetctx", NULL);
    sayp("fetch.no_get_ctx_params", nogetctx);
    printf("fetch.no_get_ctx_params.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    nofreectx = EVP_RAND_fetch(ctx, "court-rand-nofreectx", NULL);
    sayp("fetch.no_freectx", nofreectx);
    printf("fetch.no_freectx.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    nolockpair = EVP_RAND_fetch(ctx, "court-rand-nolockpair", NULL);
    sayp("fetch.half_a_lock", nolockpair);
    printf("fetch.half_a_lock.err=%lu\n", ERR_peek_error());
    ERR_clear_error();

    again = EVP_RAND_fetch(ctx, "no-such-rand", NULL);
    sayp("fetch.unknown", again);
    printf("fetch.unknown.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    again = EVP_RAND_fetch(ctx, "court-rand", "provider=other");
    sayp("fetch.rejected", again);
    printf("fetch.rejected.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    again = EVP_RAND_fetch(ctx, "courtrand", NULL);
    printf("fetch.alias_same_object=%d\n", again == base ? 1 : 0);
    EVP_RAND_free(again);

    /*
     * ---- the method object ----
     */
    if (base != NULL) {
        const char *name = EVP_RAND_get0_name(base);
        const char *desc = EVP_RAND_get0_description(base);

        printf("method.name_matches=%d\n",
               name != NULL && strcmp(name, "court-rand") == 0 ? 1 : 0);
        printf("method.description_matches=%d\n",
               desc != NULL && strcmp(desc, "court rand, the complete minimum") == 0 ? 1 : 0);
        sayp("method.provider", (const void *) EVP_RAND_get0_provider(base));
        sayn("method.is_a.identity", EVP_RAND_is_a(base, "court-rand"));
        sayn("method.is_a.alias", EVP_RAND_is_a(base, "courtrand"));
        sayn("method.is_a.other", EVP_RAND_is_a(base, "CTR-DRBG"));
        sayn("method.is_a.null_method", EVP_RAND_is_a(NULL, "court-rand"));
        sayp("method.gettable_params", (const void *) EVP_RAND_gettable_params(base));
        sayp("method.gettable_ctx_params", (const void *) EVP_RAND_gettable_ctx_params(base));
        sayp("method.settable_ctx_params", (const void *) EVP_RAND_settable_ctx_params(base));
        /* The base publishes no `get_params`, so the entry point answers 1 without a callback. */
        {
            OSSL_PARAM q[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
            size_t sz = 0;

            q[0] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &sz);
            reset_counts();
            sayn("method.get_params.ret", EVP_RAND_get_params(base, q));
            sayn("method.get_params.size", (long long) sz);
            say_vec("method.get_params.vec");
        }
        /* The full method publishes one, and the callback is what ran. */
        if (full != NULL) {
            OSSL_PARAM q[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
            size_t sz = 0;

            q[0] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &sz);
            reset_counts();
            sayn("full.get_params.ret", EVP_RAND_get_params(full, q));
            sayn("full.get_params.size", (long long) sz);
            say_vec("full.get_params.vec");
        }
        {
            struct rand_names s;

            memset(&s, 0, sizeof s);
            sayn("method.names_do_all.ret", EVP_RAND_names_do_all(base, rand_name_visitor, &s));
            sayn("method.names.count", s.count);
            sayn("method.names.saw_identity", s.saw_identity);
            sayn("method.names.saw_alias", s.saw_alias);
        }
    }

    /*
     * ---- the context, and the two NULL contracts that differ ----
     *
     * `EVP_RAND_CTX_new(NULL, NULL)` raises `EVP_R_INVALID_NULL_ALGORITHM`; `EVP_RAND_up_ref(NULL)`
     * answers 1 without raising, because the authority's static helper checks for NULL and the
     * exported wrapper is one line over it. One class refuses a NULL and the other is a no-op for
     * it, and both are measured.
     */
    sayp("ctx.new.null_method", EVP_RAND_CTX_new(NULL, NULL));
    printf("ctx.new.null_method.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    reset_counts();
    sayn("method.up_ref_null", EVP_RAND_up_ref(NULL));
    EVP_RAND_free(NULL);
    say_vec("method.null_contracts.vec");

    if (base != NULL) {
        reset_counts();
        c_base = EVP_RAND_CTX_new(base, NULL);
        sayp("ctx.new.plain", c_base);
        say_vec("plain.new.vec");
        if (c_base != NULL) {
            printf("ctx.new.rand_is_method=%d\n", EVP_RAND_CTX_get0_rand(c_base) == base ? 1 : 0);
            sayp("ctx.gettable_params", (const void *) EVP_RAND_CTX_gettable_params(c_base));
            sayp("ctx.settable_params", (const void *) EVP_RAND_CTX_settable_params(c_base));

            reset_counts();
            reset_obs();
            sayn("ctx.instantiate.ret",
                 EVP_RAND_instantiate(c_base, 256, 1, pstr, sizeof pstr, NULL));
            say_vec("plain.instantiate.vec");
            say_obs("plain.instantiate.obs");

            reset_counts();
            reset_obs();
            memset(out, 0xEE, sizeof out);
            sayn("ctx.generate.16.ret",
                 EVP_RAND_generate(c_base, out, 16, 256, 1, NULL, 0));
            sayn("ctx.generate.16.byte0", out[0]);
            sayn("ctx.generate.16.byte15", out[15]);
            sayn("ctx.generate.16.beyond_untouched", out[16] == 0xEE ? 1 : 0);
            say_obs("plain.generate.16.obs");
            say_vec("plain.generate.16.vec");

            /* An `outlen` of zero is a **success with no callback at all**: the loop's condition is
             * checked before the body, and the `max_request` read happens before the loop. */
            reset_counts();
            reset_obs();
            memset(out, 0xEE, sizeof out);
            sayn("ctx.generate.0.ret", EVP_RAND_generate(c_base, out, 0, 256, 1, NULL, 0));
            sayn("ctx.generate.0.buffer_untouched", out[0] == 0xEE ? 1 : 0);
            say_obs("plain.generate.0.obs");
            say_vec("plain.generate.0.vec");

            /* The lock is absent, so the acquisition answers 1 and every wrapped entry point is
             * free. The vector is the observation: lock and unlock stay at zero. */
            reset_counts();
            sayn("ctx.get_params_after_generate.ret", EVP_RAND_CTX_get_params(c_base, NULL));
            sayn("ctx.set_params.null", EVP_RAND_CTX_set_params(c_base, NULL));
            sayn("ctx.get_strength", (long long) EVP_RAND_get_strength(c_base));
            sayn("ctx.get_state", EVP_RAND_get_state(c_base));
            sayn("ctx.reseed.no_callback", EVP_RAND_reseed(c_base, 1, ent, sizeof ent, NULL, 0));
            sayn("ctx.verify_zeroization", EVP_RAND_verify_zeroization(c_base));
            sayn("ctx.enable_locking.no_callback", EVP_RAND_enable_locking(c_base));
            printf("ctx.enable_locking.no_callback.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            say_vec("plain.misc.vec");

            /* `nonce` with no `nonce` callback falls back to `generate`, with the strength read from
             * the context and both lengths equal. */
            reset_counts();
            reset_obs();
            memset(out, 0xEE, sizeof out);
            sayn("ctx.nonce.fallback.ret", EVP_RAND_nonce(c_base, out, 8));
            sayn("ctx.nonce.fallback.byte0", out[0]);
            sayn("ctx.nonce.fallback.byte7", out[7]);
            sayn("ctx.nonce.fallback.beyond_untouched", out[8] == 0xEE ? 1 : 0);
            say_obs("plain.nonce.fallback.obs");
            say_vec("plain.nonce.fallback.vec");

            /* The three NULL arms are checked before the lock is taken, so they raise and the
             * callback is never reached. */
            reset_counts();
            reset_obs();
            sayn("ctx.nonce.null_ctx", EVP_RAND_nonce(NULL, out, 8));
            printf("ctx.nonce.null_ctx.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            sayn("ctx.nonce.null_out", EVP_RAND_nonce(c_base, NULL, 8));
            printf("ctx.nonce.null_out.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            sayn("ctx.nonce.zero_len", EVP_RAND_nonce(c_base, out, 0));
            printf("ctx.nonce.zero_len.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            say_vec("plain.nonce.nullarms.vec");

            /* The uninstantiate zeroizes the provider's own context, and `verify_zeroization`
             * observes exactly that: the fingerprint before and after is the `fold`. */
            reset_counts();
            sayn("ctx.verify_zeroization.after_fold", EVP_RAND_verify_zeroization(c_base));
            sayn("ctx.uninstantiate.ret", EVP_RAND_uninstantiate(c_base));
            sayn("ctx.verify_zeroization.zeroized", EVP_RAND_verify_zeroization(c_base));
            say_vec("plain.uninstantiate.vec");

            /* `EVP_RAND_CTX_free(NULL)` returns, and the reference count is what decides whether a
             * `free` is a release: one `up_ref` makes a `free` a no-op. */
            reset_counts();
            sayn("ctx.up_ref", EVP_RAND_CTX_up_ref(c_base));
            EVP_RAND_CTX_free(c_base);
            say_vec("plain.up_ref_once.vec");
            EVP_RAND_CTX_free(c_base);
            say_vec("plain.up_ref_twice.vec");
        }
    }
    /* `EVP_RAND_CTX_free(NULL)` returns without raising. The observation is that the call returns
     * at all -- a transcription that dereferenced would die here. */
    EVP_RAND_CTX_free(NULL);
    printf("ctx.free_null=returned err=%lu\n", ERR_peek_error());
    ERR_clear_error();

    /* The method without a verifier answers **0**, not 1. A provider that cannot prove its state is
     * zeroized has not proven it. */
    if (noverify != NULL) {
        EVP_RAND_CTX *c = EVP_RAND_CTX_new(noverify, NULL);

        reset_counts();
        sayn("noverify.verify_zeroization", EVP_RAND_verify_zeroization(c));
        say_vec("noverify.verify.vec");
        EVP_RAND_CTX_free(c);
    }

    /*
     * ---- the lock, and the two counters that are independent ----
     */
    if (full != NULL) {
        reset_counts();
        c_full = EVP_RAND_CTX_new(full, NULL);
        printf("full.ctx.new=%d\n", c_full != NULL ? 1 : 0);
        say_vec("full.new.vec");
        if (c_full != NULL) {
            reset_counts();
            reset_obs();
            sayn("full.instantiate.ret", EVP_RAND_instantiate(c_full, 192, 0, NULL, 0, NULL));
            sayn("full.get_params.ret", EVP_RAND_CTX_get_params(c_full, NULL));
            sayn("full.set_params.ret", EVP_RAND_CTX_set_params(c_full, NULL));
            sayn("full.get_strength", (long long) EVP_RAND_get_strength(c_full));
            sayn("full.get_state", EVP_RAND_get_state(c_full));
            sayn("full.reseed.ret", EVP_RAND_reseed(c_full, 1, ent, sizeof ent, NULL, 0));
            sayn("full.verify_zeroization", EVP_RAND_verify_zeroization(c_full));
            sayn("full.uninstantiate.ret", EVP_RAND_uninstantiate(c_full));
            sayn("full.enable_locking.ret", EVP_RAND_enable_locking(c_full));
            say_obs("full.misc.obs");
            say_vec("full.misc.vec");

            /* The `nonce` callback is asked for exactly `outlen` twice: `min_len == max_len`. */
            reset_counts();
            reset_obs();
            memset(out, 0xEE, sizeof out);
            sayn("full.nonce.ret", EVP_RAND_nonce(c_full, out, 8));
            sayn("full.nonce.byte0", out[0]);
            sayn("full.nonce.byte7", out[7]);
            sayn("full.nonce.beyond_untouched", out[8] == 0xEE ? 1 : 0);
            say_obs("full.nonce.obs");
            say_vec("full.nonce.vec");
            EVP_RAND_CTX_free(c_full);
        }
    }
    /* `enable_locking` with no lock pair: fetchable, and the callback is the whole implementation
     * of the entry point -- nothing locks around it. */
    if (enableonly != NULL) {
        EVP_RAND_CTX *c = EVP_RAND_CTX_new(enableonly, NULL);

        reset_counts();
        sayn("enableonly.enable_locking.ret", EVP_RAND_enable_locking(c));
        sayn("enableonly.get_params.ret", EVP_RAND_CTX_get_params(c, NULL));
        say_vec("enableonly.vec");
        EVP_RAND_CTX_free(c);
    }

    /*
     * ---- the parent hand-off and the recursive release ----
     *
     * The child's constructor is handed `(provctx, parent_algctx, parent_dispatch)`. The probe knows
     * the parent's algorithm context because its own provider allocated it, so "the parent's
     * *algorithm* context" and "the parent's `EVP_RAND_CTX`" are distinguishable -- and only one of
     * them is what the authority passes.
     */
    if (child_meth != NULL) {
        EVP_RAND_CTX *parent, *kid, *kid2;

        reset_counts();
        g_last_algctx = NULL;
        g_last_dispatch = NULL;
        c_parent_was_null = c_parent_was_algctx = c_parent_was_ctxstruct = 0;
        c_dispatch_was_null = c_dispatch_entries = c_dispatch_first_id = 0;
        c_dispatch_same_as_before = 0;

        sayp("child.new.no_parent", EVP_RAND_CTX_new(child_meth, NULL));
        sayn("child.no_parent.was_null", c_parent_was_null);
        sayn("child.no_parent.dispatch_was_null", c_dispatch_was_null);
        say_vec("child.no_parent.vec");

        parent = EVP_RAND_CTX_new(full, NULL);
        sayp("child.parent", parent);
        /* The table the child is handed is the parent's own; the probe learns it from the first
         * child and compares the second against it, so no value is pre-loaded here. */
        g_last_dispatch = NULL;
        reset_obs();
        c_parent_was_null = c_parent_was_algctx = c_parent_was_ctxstruct = 0;
        c_dispatch_was_null = c_dispatch_entries = c_dispatch_first_id = 0;
        c_dispatch_same_as_before = 0;
        kid = EVP_RAND_CTX_new(child_meth, parent);
        sayp("child.new", kid);
        sayn("child.parent_was_algctx", c_parent_was_algctx);
        sayn("child.parent_was_ctxstruct", c_parent_was_ctxstruct);
        sayn("child.dispatch_was_null", c_dispatch_was_null);
        sayn("child.dispatch_entries", c_dispatch_entries);
        sayn("child.dispatch_first_id", c_dispatch_first_id);
        printf("child.rand_is_child_method=%d\n",
               kid != NULL && EVP_RAND_CTX_get0_rand(kid) == child_meth ? 1 : 0);
        say_vec("child.new.vec");

        /* A second child from the same parent is handed the *same table*, not a copy. */
        kid2 = EVP_RAND_CTX_new(child_meth, parent);
        sayn("child.second.dispatch_same_as_first", c_dispatch_same_as_before);
        printf("child.second.distinct_ctx=%d\n", kid2 != NULL && kid2 != kid ? 1 : 0);

        /* The release is a chain. The parent was taken reference by both children, so freeing the
         * children leaves the parent's own reference and the provider's `freectx` count unchanged --
         * and the parent's release runs exactly one more `freectx` after that. */
        reset_counts();
        EVP_RAND_CTX_free(kid2);
        say_vec("child.after_first_free.vec");
        EVP_RAND_CTX_free(kid);
        say_vec("child.after_second_free.vec");
        /* The parent itself is still usable: the children's references are what was given back. */
        sayn("child.parent_still_usable", EVP_RAND_CTX_get_params(parent, NULL));
        EVP_RAND_CTX_free(parent);
        say_vec("child.after_parent_free.vec");
    }

    /*
     * ---- the chunked generation ----
     *
     * `max_request` is asked for and the loop is driven by it. A generation of twenty over seven is
     * three calls, and *where* each landed is in the bytes.
     */
    if (smallmax != NULL) {
        reset_counts();
        reset_obs();
        c_smallmax = EVP_RAND_CTX_new(smallmax, NULL);
        printf("smallmax.ctx.new=%d\n", c_smallmax != NULL ? 1 : 0);
        if (c_smallmax != NULL) {
            reset_counts();
            reset_obs();
            memset(out, 0xEE, sizeof out);
            sayn("smallmax.generate.20.ret",
                 EVP_RAND_generate(c_smallmax, out, 20, 256, 1, ent, sizeof ent));
            sayn("smallmax.generate.20.byte0", out[0]);
            sayn("smallmax.generate.20.byte6", out[6]);
            sayn("smallmax.generate.20.byte7", out[7]);
            sayn("smallmax.generate.20.byte13", out[13]);
            sayn("smallmax.generate.20.byte14", out[14]);
            sayn("smallmax.generate.20.byte19", out[19]);
            sayn("smallmax.generate.20.byte20_untouched", out[20] == 0xEE ? 1 : 0);
            say_obs("smallmax.generate.20.obs");
            say_vec("smallmax.generate.20.vec");
            EVP_RAND_CTX_free(c_smallmax);
        }
    }

    /* A `max_request` of zero, and a `get_ctx_params` that refuses, are the same refusal: the
     * parameter cannot be read, so the loop cannot be driven. */
    if (zeromax != NULL) {
        reset_counts();
        reset_obs();
        c_zeromax = EVP_RAND_CTX_new(zeromax, NULL);
        reset_counts();
        memset(out, 0xEE, sizeof out);
        sayn("zeromax.generate.ret", EVP_RAND_generate(c_zeromax, out, 16, 256, 0, NULL, 0));
        printf("zeromax.generate.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        sayn("zeromax.generate.buffer_untouched", out[0] == 0xEE ? 1 : 0);
        say_vec("zeromax.generate.vec");
        EVP_RAND_CTX_free(c_zeromax);
    }
    if (badparams != NULL) {
        reset_counts();
        reset_obs();
        c_badparams = EVP_RAND_CTX_new(badparams, NULL);
        reset_counts();
        memset(out, 0xEE, sizeof out);
        sayn("badparams.generate.ret", EVP_RAND_generate(c_badparams, out, 16, 256, 0, NULL, 0));
        printf("badparams.generate.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        sayn("badparams.generate.buffer_untouched", out[0] == 0xEE ? 1 : 0);
        sayn("badparams.get_strength", (long long) EVP_RAND_get_strength(c_badparams));
        sayn("badparams.get_state", EVP_RAND_get_state(c_badparams));
        say_vec("badparams.vec");
        EVP_RAND_CTX_free(c_badparams);
    }

    /*
     * ---- `do_all`, which counts what was *constructed* rather than what was published ----
     *
     * Twelve algorithms are published and four cannot be constructed, so the walk counts eight.
     */
    {
        struct rand_seen s;

        memset(&s, 0, sizeof s);
        EVP_RAND_do_all_provided(ctx, rand_visitor, &s);
        sayn("do_all.count", s.count);
        sayn("do_all.saw_court_rand", s.saw_plain);
        sayn("do_all.saw_a_refused_one", s.saw_refused);
    }
    printf("do_all.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("get_seed=NOT_MEASURED_INTERNAL_TO_PHASE_9\n");
    printf("clear_seed=NOT_MEASURED_INTERNAL_TO_PHASE_9\n");
    printf("can_seed=NOT_MEASURED_INTERNAL_TO_PHASE_9\n");

    reset_counts();
    EVP_RAND_free(base);
    EVP_RAND_free(full);
    EVP_RAND_free(noverify);
    EVP_RAND_free(enableonly);
    EVP_RAND_free(child_meth);
    EVP_RAND_free(smallmax);
    EVP_RAND_free(zeromax);
    EVP_RAND_free(badparams);
    EVP_RAND_free(nogen);
    EVP_RAND_free(nogetctx);
    EVP_RAND_free(nofreectx);
    EVP_RAND_free(nolockpair);
    sayn("unload", OSSL_PROVIDER_unload(p));
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
