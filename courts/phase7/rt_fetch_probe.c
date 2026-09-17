/*
 * RT-FETCH -- the fetch core, from the one angle a probe can be asked in 7.1.
 *
 * What this court can observe, and what it cannot
 * -----------------------------------------------
 * 7.1 lands the fetch *machinery*: the algorithm walk, `ossl_method_construct`, and the method
 * store `crypto/property/property.c` implements. None of it is exported. `libcrypto.ld`'s
 * version script hides every `ossl_*` name from the DSO, and a probe is compiled against the
 * *installed* headers and linked against `libcrypto.so`, so it cannot call one of them -- this
 * is the same boundary Phase 6 met with the property grammar, and the same answer applies: what
 * a consumer can reach was `OSSL_LIB_CTX_get_data`, and what a consumer reaches now that 7.2
 * and 7.3a have landed is `EVP_MD_fetch` and its siblings.
 *
 * **7.3a's `EVP_MD` is what changed that**, and this probe now observes the fetch path itself.
 * Before it, the store and the walk were reachable from no probe at all: every entry point is
 * `ossl_*` or `evp_*` and the DSO hides all of them. `EVP_MD_fetch` is the first *exported*
 * consumer of the fetch path, so the second half of this probe is the observation 7.2's exit
 * criterion named — a query that selects, a query that **rejects**, and the context's default
 * properties doing both from the other side.
 *
 * What it observes, in three parts:
 *
 *   * `OSSL_LIB_CTX_get_data(ctx, 0)` -- `OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX` -- now answers a
 *     pointer, because `context_init` builds the store. That is the whole of D142's observable
 *     consequence, and the relations below pin its *shape*: stable within a context, distinct
 *     between contexts, distinct from the default context's, and NULL for every index the
 *     authority's own `switch` has no arm for.
 *   * `OSSL_PROVIDER_load` and `OSSL_PROVIDER_unload` on a probe-registered builtin provider
 *     reach `evp_method_store_cache_flush` and `evp_method_store_remove_all_provided` through
 *     `crypto/provider_core.c`'s two store bridges: the first activation of a provider flushes
 *     the store's query cache, and the last deactivation removes that provider's methods from
 *     it. Both are *delegations* into this stratum's store, and both are on the public path.
 *     The flush's *result* is not reproducible -- its strategy is stochastic and its seed is
 *     the CPU timestamp counter -- so what is compared is that the calls happen, answer
 *     success, and leave the store usable. `src/property/store.rs` says the same thing at the
 *     flush, and the unit test for the threshold asserts the flag rather than the outcome.
 *   * **the resolver**, added by 7.3a. `crypto/evp/evp_fetch.c` has no exported entry point of
 *     its own -- `EVP_MD_fetch` is the first *exported* consumer of it -- so until a method class
 *     existed the store's selection was observable from nothing at all. The provider below
 *     publishes one digest under three names with one property definition, and the block
 *     observes: a plain fetch, the cache answering the same object a second time, an alias
 *     resolving to it and reporting the canonical name, the declared property selecting it, a
 *     property that **contradicts** it rejecting it, a name nobody publishes, the legacy NID,
 *     the reference count surviving a free, the context's own default properties rejecting and
 *     then releasing, and finally the same fetch with the provider **unloaded** -- where the
 *     error *reason* is the observation rather than the NULL.
 *   * **the context path**, added by 7.3d-ii. The resolver's own digest publishes no structural
 *     functions, so the first `EVP_MD_CTX` observations in the project needed an algorithm with
 *     them: two more names are published, one with all six structural callbacks and one without
 *     `squeeze`, and the provider **counts its own callbacks** so the transcript says which arm of
 *     the initialise ran, how many times, and in what order. The digest value is a function of what
 *     was fed, so "the implementation ran" is distinguishable from "some implementation ran"; the
 *     method's size and the context's size are deliberately different, so that
 *     `EVP_MD_CTX_get_size_ex`'s choice between the two questions is observable rather than
 *     invisible; and every refusal is compared with the reason the authority raises.
 *
 * What the resolver is, and why it is shaped the way it is
 * --------------------------------------------------------
 * The provider publishes **one digest, three names and one property definition**
 * (`provider=court`). One name is the identity, two are aliases; the property is what the
 * negative-selection observation rejects. The digest implements only the *one-shot*
 * `OSSL_FUNC_DIGEST_DIGEST` plus `OSSL_FUNC_DIGEST_GET_PARAMS`, which is the smallest shape
 * `evp_md_from_algorithm`'s structural check accepts -- a count of zero structural functions is
 * legal when a standalone `digest` is present -- so the probe exercises that arm rather than the
 * five-function one. `get_params` is not optional: `evp_md_cache_constants` asks it for the size
 * and the block size and a provider that does not answer both **fails its own fetch**.
 *
 * Deliberately not observed
 * -------------------------
 *   * **slots 10, 11, 15 and 20** (`encoder_store`, `decoder_store`, `store_loader_store`,
 *     `decoder_cache`) are Phase 10's, and the authority fills all four. A probe that printed
 *     them would report a *missing stratum* as a residual, which is the obligation ledger's
 *     business rather than a court's -- the same distinction `RT-LIBCTX` makes for its own
 *     deferred slots.
 *   * **a child context's store.** `OSSL_LIB_CTX_new_child` needs a core handle and a
 *     `OSSL_DISPATCH` table, which `RT-PROVIDER-3P` is the court that builds; a child's slot 0
 *     is a real observation and is available there, and it is still deferred: a fetch against a
 *     child's scope needs a *provider* published into that child, which `RT-PROVIDER-3P`'s is to
 *     build, not this court's to approximate.
 *   * **four authority faults**, each printed as `NOT_MEASURED_AUTHORITY_FAULTS` rather than
 *     executed: the three NULL method callbacks `docs/SECURITY_DIVERGENCE_POLICY.md`
 *     D-MD-NULL-CALLBACK-1 measures, and `EVP_MD_do_all_provided` with a NULL visitor
 *     (D-MD-DOALL-NULL-1). Each is reachable through a documented entry point, so the boundary is
 *     visible in the transcript instead of absent from it.
 *
 * Addresses are never printed. Every observation is a relation between two pointers this probe
 * holds (`same` / `different`), a presence answer (`NULL` / `nonnull`), or a return code,
 * because the two libraries' addresses are not comparable and printing one would compare the
 * probe's heap layout rather than the library's behaviour.
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

/* The index numbers, from `include/internal/cryptlib.h` of the admitted authority. They are
 * not in any installed header, so a consumer that passes one is passing a bare integer --
 * which is what this probe does.
 *
 *   0 EVP_METHOD_STORE  1 PROVIDER_STORE   2 PROPERTY_DEFN   3 PROPERTY_STRING
 *   4 NAMEMAP           5 DRBG             6 DRBG_NONCE      7 (was CRNG test data)
 *   8 (was THREAD_EVENT) 9 FIPS_PROV      10 ENCODER_STORE  11 DECODER_STORE
 *  12 SELF_TEST_CB     13 BIO_PROV        14 GLOBAL_PROPERTIES
 *  15 STORE_LOADER     16 PROVIDER_CONF    17 BIO_CORE       18 CHILD_PROVIDER
 *  19 THREAD           20 DECODER_CACHE    21 COMP_METHODS   22 INDICATOR_CB
 *
 * `OSSL_LIB_CTX_MAX_INDEXES` is 22 and the function does not consult it; 22 is a live index and
 * 23 is the first one the `default:` arm answers. */
#define IDX_EVP_METHOD_STORE 0

/* The eighteen indices the authority answers a pointer for. */
#define LIVE_SLOTS 18

/* The index this stratum fills. */
#define FILLED_HERE 1

/* The four slots this stratum's *object* also fits but which belong to a stratum that has not
 * landed: named so the scope line says how many are missing rather than leaving it implied. */
#define PHASE10_SLOTS 4

/* The indices the authority answers NULL for: 7 and 8 are unassigned, 9 is a FIPS-only index
 * in a profile that is not a FIPS build, 13 was `BIO_PROV` and has no arm, and everything from
 * 23 up is past the end of the switch. -1 is the negative case, which `default:` answers too. */
static const int dead_slots[] = { -1, 7, 8, 9, 13, 23, 24, 31, 255 };
#define DEAD_COUNT ((int) (sizeof dead_slots / sizeof dead_slots[0]))

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

static void says(const char *key, const char *s)
{
    printf("%s=%s err=%lu\n", key, s == NULL ? "(null)" : s, ERR_peek_error());
    ERR_clear_error();
}

/* ---- the probe's own provider, so that the two store bridges are reachable ---- */

static char court_marker;

static void court_teardown(void *provctx)
{
    (void) provctx;
}

/*
 * The digest this provider publishes, and why it is shaped the way it is.
 *
 * `evp_md_from_algorithm` counts the *structural* functions it finds -- `newctx`, `init`,
 * `update`, `final`, `squeeze`, `freectx` -- and accepts a count of 5 or 6, or a count of 0 when
 * there is a standalone one-shot `digest`. This provider publishes **only the one-shot** and the
 * two parameters, which is the smallest legal shape and exercises that arm of the check: a
 * provider that published `update` without `newctx` would be refused by the authority and by the
 * candidate alike, and would prove nothing.
 *
 * `get_params` is not optional. `evp_md_cache_constants` asks it for `size` and `blocksize` at
 * fetch time and a digest that does not answer both **fails its own fetch** with
 * `EVP_R_CACHE_CONSTANTS_FAILED` -- so a resolver without this function would make the court read
 * the authority's refusal as a candidate divergence.
 */
#define COURT_MD_SIZE 32
#define COURT_MD_BLOCK_SIZE 64

static int court_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    size_t size = COURT_MD_SIZE;
    size_t blocksize = COURT_MD_BLOCK_SIZE;

    p = OSSL_PARAM_locate(params, "size");
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    p = OSSL_PARAM_locate(params, "blocksize");
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blocksize))
        return 0;
    return 1;
}

static int court_digest(void *provctx, const unsigned char *in, size_t inl,
                        unsigned char *out, size_t *outl, size_t outsz)
{
    size_t i;

    (void) provctx;
    (void) in;
    (void) inl;
    if (outsz < COURT_MD_SIZE)
        return 0;
    /* A deterministic byte pattern, so the transcript can prove the *implementation* the fetch
     * resolved is the one this provider published rather than a plausible stand-in. The digest's
     * value is not a security claim and the probe never prints it as one: it prints whether the
     * call answered, and the size. */
    for (i = 0; i < COURT_MD_SIZE; i++)
        out[i] = (unsigned char)(i + 1);
    *outl = COURT_MD_SIZE;
    return 1;
}

/* ---- the context-path algorithm, and why there are two of them ---- */

/*
 * `evp_md_from_algorithm` counts the *structural* functions it finds and accepts a count of 5 or
 * 6, or a count of 0 when a standalone one-shot is present. The digest above exercises the 0 arm
 * and is the smallest legal shape. These two exercise the other two arms, and they are the only
 * reason `EVP_MD_CTX` has anything to run on:
 *
 *   * `court-md-ctx`  publishes all six -- `newctx`, `init`, `update`, `final`, `squeeze` and
 *     `freectx` -- so the squeeze path is reachable;
 *   * `court-md-ctx5` publishes the same five **without** `squeeze`, so the count-5 arm is
 *     exercised and `EVP_DigestSqueeze` is a refusal with its own reason rather than a call.
 *
 * The two differ in one more place, and it is deliberate: the **context's** `size` parameter.
 * `get_params` answers 32 for both, which `evp_md_cache_constants` stores as `md_size`, so
 * `EVP_MD_get_size` says 32 either way. `court-md-ctx`'s context answers **24**, which is what
 * makes `EVP_MD_CTX_get_size_ex`'s two paths distinguishable from outside the library: it asks
 * the *context* first, and a provider whose two answers agree would make the choice invisible.
 *
 * The **counters below are the observation**. A probe can see which of the twenty-five
 * `OSSL_FUNC_DIGEST_*` callbacks ran, in what order and how many times, by counting them in its
 * own address space -- and the digest value is a function of what was fed, so the transcript also
 * distinguishes "the implementation ran" from "some implementation ran". Neither is a security
 * claim and neither is printed as one.
 */
#define COURT_CTX_MD_SIZE 32
#define COURT_CTX_SIZE 24
#define COURT_CTX_BLOCK 64

struct court_dctx {
    unsigned char buf[COURT_CTX_BLOCK];
    size_t len;
    unsigned long sum;
};

static int ctx_new_calls, ctx_free_calls, ctx_dup_calls;
static int ctx_init_calls, ctx_update_calls, ctx_final_calls, ctx_squeeze_calls;
static int ctx_setparams_calls, ctx_getparams_calls;

static void *ctx_newctx(void *provctx)
{
    struct court_dctx *d;

    (void) provctx;
    ctx_new_calls++;
    d = malloc(sizeof *d);
    if (d == NULL)
        return NULL;
    memset(d, 0, sizeof *d);
    return d;
}

static void ctx_freectx(void *dctx)
{
    ctx_free_calls++;
    free(dctx);
}

static void *ctx_dupctx(void *dctx)
{
    struct court_dctx *to;

    ctx_dup_calls++;
    if (dctx == NULL)
        return NULL;
    to = malloc(sizeof *to);
    if (to == NULL)
        return NULL;
    memcpy(to, dctx, sizeof *to);
    return to;
}

static int ctx_init(void *dctx, const OSSL_PARAM *params)
{
    struct court_dctx *d = dctx;

    (void) params;
    ctx_init_calls++;
    d->len = 0;
    d->sum = 0;
    return 1;
}

static int ctx_update(void *dctx, const unsigned char *in, size_t inl)
{
    struct court_dctx *d = dctx;
    size_t i;

    ctx_update_calls++;
    for (i = 0; i < inl && d->len < COURT_CTX_BLOCK; i++, d->len++)
        d->buf[d->len] = in[i];
    for (i = 0; i < inl; i++)
        d->sum = (d->sum * 31 + in[i]) & 0xffff;
    return 1;
}

/* The emitted value is a function of what was fed: the first byte is the length, the next two are
 * a running hash of the bytes fed, and the fourth is the first byte retained. `outsz` is the
 * caller's buffer size and the answer is exactly that long, which is what a XOF does. */
static int ctx_emit(struct court_dctx *d, unsigned char *out, size_t *outl, size_t outsz)
{
    size_t i;

    if (outsz < 4) {
        *outl = 0;
        return 0;
    }
    out[0] = (unsigned char) (d->len & 0xff);
    out[1] = (unsigned char) (d->sum & 0xff);
    out[2] = (unsigned char) ((d->sum >> 8) & 0xff);
    out[3] = d->buf[0];
    for (i = 4; i < outsz; i++)
        out[i] = (unsigned char) ((i * 7) & 0xff);
    *outl = outsz;
    return 1;
}

static int ctx_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz)
{
    ctx_final_calls++;
    return ctx_emit(dctx, out, outl, outsz);
}

/* Squeeze is the repeatable read: it writes the same bytes and touches nothing, which is what
 * makes a second call on the same context an observation rather than a repeat. */
static int ctx_squeeze(void *dctx, unsigned char *out, size_t *outl, size_t outsz)
{
    ctx_squeeze_calls++;
    return ctx_emit(dctx, out, outl, outsz);
}

static int ctx_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    size_t size = COURT_CTX_MD_SIZE;
    size_t blocksize = COURT_CTX_BLOCK;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    p = OSSL_PARAM_locate(params, "blocksize");
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blocksize))
        return 0;
    return 1;
}

/* The context-level parameter read, and the one place the two algorithms differ. `micalg` is
 * answered as a string so `EVP_MD_CTX_ctrl`'s *get* direction has something to read. */
static int ctx_get_ctx_params_of(void *dctx, OSSL_PARAM params[], size_t size)
{
    OSSL_PARAM *p;

    (void) dctx;
    ctx_getparams_calls++;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_MICALG);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "court-micalg"))
        return 0;
    return 1;
}

static int ctx_get_ctx_params(void *dctx, OSSL_PARAM params[])
{
    return ctx_get_ctx_params_of(dctx, params, COURT_CTX_SIZE);
}

static int ctx5_get_ctx_params(void *dctx, OSSL_PARAM params[])
{
    return ctx_get_ctx_params_of(dctx, params, COURT_CTX_MD_SIZE);
}

static int ctx_set_ctx_params(void *dctx, const OSSL_PARAM *params)
{
    (void) dctx;
    (void) params;
    ctx_setparams_calls++;
    return 1;
}

static const OSSL_PARAM *ctx_gettable_ctx_params(void *dctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_DIGEST_PARAM_MICALG, NULL, 0),
        OSSL_PARAM_END
    };

    (void) dctx;
    (void) provctx;
    return gettable;
}

static const OSSL_PARAM *ctx_settable_ctx_params(void *dctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
        OSSL_PARAM_END
    };

    (void) dctx;
    (void) provctx;
    return settable;
}

/* The six-function dispatch table and the five-function one, sharing every callback. A copy
 * rather than a macro because a probe is read line by line and a table is the thing being read. */
static const OSSL_DISPATCH court_ctx_fns[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) ctx_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) ctx_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) ctx_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) ctx_final },
    { OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void)) ctx_squeeze },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) ctx_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) ctx_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) ctx_get_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void)) ctx_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void)) ctx_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void)) ctx_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void)) ctx_settable_ctx_params },
    { 0, NULL }
};

static const OSSL_DISPATCH court_ctx5_fns[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) ctx_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) ctx_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) ctx_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) ctx_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) ctx_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) ctx_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) ctx_get_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void)) ctx_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void)) ctx5_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void)) ctx_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void)) ctx_settable_ctx_params },
    { 0, NULL }
};

/* The nine counters as one observation. A caller that printed them one per line would make an
 * accidental reordering of two of them a residual; one vector makes the whole call path one
 * comparable fact, which is what it is. */
static void say_ctx_activity(const char *key)
{
    printf("%s=%d,%d,%d,%d,%d,%d,%d,%d,%d err=%lu\n", key,
           ctx_new_calls, ctx_free_calls, ctx_dup_calls, ctx_init_calls,
           ctx_update_calls, ctx_final_calls, ctx_squeeze_calls,
           ctx_setparams_calls, ctx_getparams_calls, ERR_peek_error());
    ERR_clear_error();
}

/* The namemap visitor both a `METH` method's and a fetched method's name list are walked with.
 * It records *which* names arrived rather than how many in what order, because the order is the
 * namemap's insertion order and this court's business is the set. */
struct name_seen {
    int saw_identity;
    int saw_alias;
    int count;
};

static void name_visitor(const char *name, void *data)
{
    struct name_seen *s = data;

    s->count++;
    if (strcmp(name, "court-md") == 0)
        s->saw_identity = 1;
    if (strcmp(name, "courtmd") == 0)
        s->saw_alias = 1;
}

/* A `METH` digest's `init`, so the hand-built method has something to store and the getter has
 * something to answer. The accessor block below stores it and then **calls it through a context**,
 * which is what makes the legacy arm of `evp_md_init_internal` observable from a probe at all. */
static int meth_init_calls;
static int meth_md_init(EVP_MD_CTX *ctx)
{
    (void) ctx;
    meth_init_calls++;
    return 1;
}

static const OSSL_DISPATCH court_digest_fns[] = {
    { OSSL_FUNC_DIGEST_DIGEST, (void (*)(void)) court_digest },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) court_get_params },
    { 0, NULL }
};

/* The published name list: three aliases, the first of which is the identity. The provider's
 * property definition is what the *negative* selection below rejects. Two more algorithms follow
 * for the context path -- see the note above `court_ctx_fns`. */
static const OSSL_ALGORITHM court_digests[] = {
    { "court-md:Court-MD:courtmd", "provider=court", court_digest_fns, "court digest" },
    { "court-md-ctx:Court-MD-ctx:courtmdctx", "provider=court", court_ctx_fns,
      "court digest with a context" },
    { "court-md-ctx5:Court-MD-ctx5:courtmdctx5", "provider=court", court_ctx5_fns,
      "court digest without squeeze" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_DIGEST)
        return court_digests;
    /* Every other operation is empty, so the algorithm walk visits nothing for it and this
     * provider's only contribution is the digest. */
    return NULL;
}

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) court_teardown },
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

int main(void)
{
    OSSL_LIB_CTX *ctx, *other;
    OSSL_PROVIDER *p, *q;
    void *store, *store_again, *default_store, *other_store;
    int i, ret;

    /* Line-buffer everything: a probe that dies part way through must still have its
     * observations in the pipe, or a crash reads as agreement. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    other = OSSL_LIB_CTX_new();
    if (ctx == NULL || other == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }

    /* ---- the store's shape in the index table ---- */
    sayn("slot.live", LIVE_SLOTS);
    sayn("slot.filled_here", FILLED_HERE);
    sayn("slot.phase10_unfilled", PHASE10_SLOTS);

    store = OSSL_LIB_CTX_get_data(ctx, IDX_EVP_METHOD_STORE);
    sayp("slot.evp_store", store);
    store_again = OSSL_LIB_CTX_get_data(ctx, IDX_EVP_METHOD_STORE);
    printf("slot.evp_store.stable=%d err=%lu\n", store == store_again ? 1 : 0,
           ERR_peek_error());
    ERR_clear_error();

    other_store = OSSL_LIB_CTX_get_data(other, IDX_EVP_METHOD_STORE);
    sayp("slot.other_ctx", other_store);
    printf("slot.ctx.vs.other=%d err=%lu\n", store != other_store ? 1 : 0,
           ERR_peek_error());
    ERR_clear_error();

    /* The default context is reachable through a NULL context on both sides, and its store is
     * not this context's: `context_init` builds one per context, and the default is just
     * another context. */
    default_store = OSSL_LIB_CTX_get_data(NULL, IDX_EVP_METHOD_STORE);
    sayp("slot.default", default_store);
    printf("slot.default.vs.ctx=%d err=%lu\n", default_store != store ? 1 : 0,
           ERR_peek_error());
    ERR_clear_error();
    printf("slot.default.stable=%d err=%lu\n",
           default_store == OSSL_LIB_CTX_get_data(NULL, IDX_EVP_METHOD_STORE) ? 1 : 0,
           ERR_peek_error());
    ERR_clear_error();

    /* ---- the dead indices, which is where a candidate that guessed would differ ---- */
    for (i = 0; i < DEAD_COUNT; i++) {
        char key[64];

        snprintf(key, sizeof key, "slot.dead.%d", dead_slots[i]);
        sayp(key, OSSL_LIB_CTX_get_data(ctx, dead_slots[i]));
    }

    /* ---- the default-properties surface: this stratum's first *exports* ---- */
    /*
     * Unlike everything above, these are exported functions, so the probe calls them directly.
     * They are the half of `evp_fetch.c` that needs no method objects: they read and write the
     * context's global-property list, render it back to text, and flush the store's cache.
     *
     * The text is compared, not just the return code, because the text is what every activated
     * provider is handed; and the two directions of `EVP_default_properties_enable_fips` are
     * compared because enabling merges `fips=yes` while disabling merges the **negative** form.
     */
    {
        char *props;

        sayn("props.set", EVP_set_default_properties(ctx, "fips=yes"));
        props = EVP_get1_default_properties(ctx);
        says("props.get", props);
        OPENSSL_free(props);

        sayn("props.fips_after_set", EVP_default_properties_is_fips_enabled(ctx));
        sayn("props.enable_fips_off", EVP_default_properties_enable_fips(ctx, 0));
        props = EVP_get1_default_properties(ctx);
        says("props.get_after_disable", props);
        OPENSSL_free(props);
        sayn("props.fips_after_disable", EVP_default_properties_is_fips_enabled(ctx));

        /* A query the grammar refuses: the *reason* is part of the observation, so the error
         * queue is printed rather than cleared and ignored. */
        sayn("props.set_bad", EVP_set_default_properties(ctx, "===no"));
        printf("props.bad.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        props = EVP_get1_default_properties(ctx);
        says("props.get_after_bad", props);
        OPENSSL_free(props);

        /* A NULL query clears them, and the answer is an *empty string* rather than NULL --
         * a distinction a caller can see, because it is a valid pointer to free and to print. */
        sayn("props.set_null", EVP_set_default_properties(ctx, NULL));
        props = EVP_get1_default_properties(ctx);
        printf("props.get_null.is_empty=%d\n", props != NULL && props[0] == '\0' ? 1 : 0);
        OPENSSL_free(props);
    }

    /* ---- the two store bridges, on the public path ---- */
    ret = OSSL_PROVIDER_add_builtin(ctx, "court-fetch", court_provider_init);
    sayn("add_builtin.ret", ret);

    /* The **first** activation is the one that flushes the store's query cache, so this load is
     * the observation: `ossl_provider_activate` calls `provider_flush_store_cache` when the
     * activation count reaches 1, and that reaches `evp_method_store_cache_flush`. */
    p = OSSL_PROVIDER_load(ctx, "court-fetch");
    printf("load.nonnull=%d\n", p != NULL ? 1 : 0);
    if (p == NULL) {
        printf("load.failed=1\n");
        OSSL_LIB_CTX_free(other);
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    /* The store survived the flush delegation, and it is the same object. */
    printf("load.store.stable=%d err=%lu\n",
           store == OSSL_LIB_CTX_get_data(ctx, IDX_EVP_METHOD_STORE) ? 1 : 0,
           ERR_peek_error());
    ERR_clear_error();

    /* A second load takes the activation count to 2, where the authority answers 1 **without**
     * flushing. The observable is that the object is the same and the answer is non-NULL. */
    q = OSSL_PROVIDER_load(ctx, "court-fetch");
    printf("load_again.same_object=%d\n", q == p ? 1 : 0);

    /*
     * ---- the fetch path itself, which 7.3a's EVP_MD makes reachable ----
     *
     * Everything above this point observes the *machinery*: the store's shape and the two
     * bridges that delegate into it. These observations are the ones 7.2's exit criterion named
     * and could not reach until a class existed to fetch through -- a query that selects, a
     * query that **rejects**, and the default-properties merge that does the same thing from the
     * other side.
     *
     * The provider is **loaded** here and unloaded below, which is the whole reason the two
     * blocks are in this order: this one observes resolution, and the next observes the same
     * call with nothing to resolve against -- and the *reason* the authority answers, which is
     * the one thing an otherwise-correct transcription gets wrong without any other symptom.
     */
    {
        EVP_MD *md, *md2, *md3;
        const char *nm;

        md = EVP_MD_fetch(ctx, "court-md", NULL);
        printf("fetch.plain_nonnull=%d\n", md != NULL ? 1 : 0);
        if (md != NULL) {
            printf("fetch.plain_name_matches=%d\n",
                   (nm = EVP_MD_get0_name(md)) != NULL && strcmp(nm, "court-md") == 0 ? 1 : 0);
            printf("fetch.plain_size=%d\n", EVP_MD_get_size(md));
            printf("fetch.plain_block_size=%d\n", EVP_MD_get_block_size(md));
            printf("fetch.plain_type=%d\n", EVP_MD_get_type(md));

            /* The second fetch of the same name under the same query comes from the *cache*, so
             * it is the same object with a second reference -- which is observable, and is the
             * one place a transcription that forgot the cache would still look correct. */
            md2 = EVP_MD_fetch(ctx, "court-md", NULL);
            printf("fetch.cached_same_object=%d\n", md2 == md ? 1 : 0);
            printf("fetch.cached_nonnull=%d\n", md2 != NULL ? 1 : 0);
            EVP_MD_free(md2);

            /* An alias resolves to the same method: the namemap registered all three names. */
            md3 = EVP_MD_fetch(ctx, "courtmd", NULL);
            printf("fetch.alias_same_object=%d\n", md3 == md ? 1 : 0);
            printf("fetch.alias_name_matches=%d\n",
                   md3 != NULL && (nm = EVP_MD_get0_name(md3)) != NULL
                       && strcmp(nm, "court-md") == 0 ? 1 : 0);
            EVP_MD_free(md3);

            /* The positive selection: the property the provider declares. */
            md3 = EVP_MD_fetch(ctx, "court-md", "provider=court");
            printf("fetch.selected_nonnull=%d\n", md3 != NULL ? 1 : 0);
            EVP_MD_free(md3);

            /* **The negative selection.** The algorithm exists and the query forbids its only
             * property, so the fetch must fail rather than fall back. */
            md3 = EVP_MD_fetch(ctx, "court-md", "provider=other");
            printf("fetch.rejected_null=%d\n", md3 == NULL ? 1 : 0);
            printf("fetch.rejected.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            EVP_MD_free(md3);

            /* A name nobody publishes, for the other error reason. */
            md3 = EVP_MD_fetch(ctx, "no-such-md", NULL);
            printf("fetch.unknown_null=%d\n", md3 == NULL ? 1 : 0);
            printf("fetch.unknown.err=%lu\n", ERR_peek_error());
            ERR_clear_error();

            /* The reference count: an extra up_ref survives the first free and the object is
             * still usable, which is the only observable the refcnt has. */
            printf("fetch.up_ref=%d\n", EVP_MD_up_ref(md));
            EVP_MD_free(md);
            printf("fetch.after_up_ref_free_size=%d\n", EVP_MD_get_size(md));
            EVP_MD_free(md);

            /*
             * **The default properties do the same thing from the other side.** A context-wide
             * query is merged with the caller's before matching, so setting `provider=other` on
             * the context makes the same fetch fail -- and clearing them makes it work again.
             * That is the property-string step 6.8's two divergences recorded as unreachable,
             * observed here through the fetch path rather than through the store.
             */
            printf("defaults.set=%d\n", EVP_set_default_properties(ctx, "provider=other"));
            md = EVP_MD_fetch(ctx, "court-md", NULL);
            printf("defaults.rejects_null=%d\n", md == NULL ? 1 : 0);
            ERR_clear_error();
            EVP_MD_free(md);
            printf("defaults.clear=%d\n", EVP_set_default_properties(ctx, NULL));
            md = EVP_MD_fetch(ctx, "court-md", NULL);
            printf("defaults.cleared_nonnull=%d\n", md != NULL ? 1 : 0);
            EVP_MD_free(md);
        } else {
            printf("fetch.failed=1\n");
        }
    }

    /*
     * ---- 7.3d-ii: the context path, which is what the two context algorithms made reachable ----
     *
     * `EVP_MD_CTX` is the object every digest call is actually made on, and until this subphase no
     * probe could reach one: the context half was not transcribed, and the resolver above publishes
     * a method with no structural functions at all -- so `EVP_DigestInit_ex` on it would have
     * reached a NULL `newctx`. The two context algorithms are the ones that give a context
     * something to run, and the observations below are of three kinds:
     *
     *   * **the call path.** The provider counts its own callbacks, so the transcript says which of
     *     them ran, how many times -- a transcription that took the wrong arm of any of the
     *     initialise's four branches, or that reused an algorithm context where the authority
     *     duplicates one, cannot produce the same vector;
     *   * **the value.** The digest is a function of what was fed (the length, a running hash of
     *     the bytes, and the first retained byte), so "the implementation ran" is distinguishable
     *     from "some implementation ran";
     *   * **the refusals**, each with the reason the authority raises: a second final, a squeeze on
     *     a method that publishes five structural functions, and the two size answers that differ
     *     between the method and the context.
     *
     * The block runs **before** the provider is unloaded, unlike the accessor block below it, which
     * is why it is here and not at the end: a fetch of an unloaded provider's algorithm fails on
     * both sides and would make every observation in it vacuous.
     */
    {
        EVP_MD *cmd = EVP_MD_fetch(ctx, "court-md-ctx", NULL);
        EVP_MD *cmd5 = EVP_MD_fetch(ctx, "court-md-ctx5", NULL);
        EVP_MD_CTX *c, *copyc, *dupc;
        unsigned char out[64];
        unsigned int outl;
        size_t xoflen;
        EVP_MD *owned;
        char micalg[64];

        sayp("ctxmd.fetch", cmd);
        sayp("ctxmd5.fetch", cmd5);
        /* The method-level size, from the fetch-time `get_params` answer of 32. */
        sayn("ctxmd.method_size", EVP_MD_get_size(cmd));
        say_ctx_activity("ctx.activity.pristine");

        /* -- a fresh context, and the five accessors that read one -- */
        c = EVP_MD_CTX_new();
        sayp("ctx.new", c);
        printf("ctx.new.reqdigest_null=%d\n", EVP_MD_CTX_get0_md(c) == NULL ? 1 : 0);
        printf("ctx.new.md_data_null=%d\n", EVP_MD_CTX_get0_md_data(c) == NULL ? 1 : 0);
        printf("ctx.new.update_null=%d\n", EVP_MD_CTX_update_fn(c) == NULL ? 1 : 0);
        printf("ctx.new.pkey_null=%d\n", EVP_MD_CTX_get_pkey_ctx(c) == NULL ? 1 : 0);
        printf("ctx.new.get1_md_null=%d\n", EVP_MD_CTX_get1_md(c) == NULL ? 1 : 0);
        /* -1 **with an error**, because the fall-through asks `EVP_MD_get_size(NULL)`. */
        sayn("ctx.new.get_size", EVP_MD_CTX_get_size_ex(c));

        /* -- the initialise, and the two size questions that have two different answers -- */
        sayn("ctx.init", EVP_DigestInit_ex(c, cmd, NULL));
        printf("ctx.init.reqdigest_is_method=%d\n", EVP_MD_CTX_get0_md(c) == cmd ? 1 : 0);
        printf("ctx.init.deprecated_is_method=%d\n", EVP_MD_CTX_md(c) == cmd ? 1 : 0);
        owned = EVP_MD_CTX_get1_md(c);
        printf("ctx.init.get1_is_method=%d\n", owned == cmd ? 1 : 0);
        EVP_MD_free(owned);
        /* The context's own `size` is 24 where the method's is 32: `get_size_ex` asks the context
         * first, so the two being different is what makes the choice observable from outside. */
        sayn("ctx.init.context_size", EVP_MD_CTX_get_size_ex(c));
        printf("ctx.init.md_data_null=%d\n", EVP_MD_CTX_get0_md_data(c) == NULL ? 1 : 0);
        printf("ctx.init.update_null=%d\n", EVP_MD_CTX_update_fn(c) == NULL ? 1 : 0);
        sayp("ctx.init.gettable_params", (const void *) EVP_MD_CTX_gettable_params(c));
        sayp("ctx.init.settable_params", (const void *) EVP_MD_CTX_settable_params(c));
        /* The same two questions asked of the *method*, which is the other entry point. */
        sayp("ctxmd.gettable_ctx_params", (const void *) EVP_MD_gettable_ctx_params(cmd));
        sayp("ctxmd.settable_ctx_params", (const void *) EVP_MD_settable_ctx_params(cmd));
        say_ctx_activity("ctx.activity.after_init");

        /* -- update, and the final -- */
        sayn("ctx.update", EVP_DigestUpdate(c, "abcd", 4));
        sayn("ctx.update.zero", EVP_DigestUpdate(c, NULL, 0));
        memset(out, 0xEE, sizeof out);
        outl = 0;
        sayn("ctx.final.return", EVP_DigestFinal_ex(c, out, &outl));
        sayn("ctx.final.outl", (long long) outl);
        /* The four leading bytes are the length, the two halves of a running hash of what was fed,
         * and the first retained byte -- so these say *which* implementation ran. */
        sayn("ctx.final.byte0", out[0]);
        sayn("ctx.final.byte1", out[1]);
        sayn("ctx.final.byte2", out[2]);
        sayn("ctx.final.byte3", out[3]);
        sayn("ctx.final.byte23", out[23]);
        /* And nothing past the provider's answer was written. */
        sayn("ctx.final.beyond_outl_untouched", out[24] == 0xEE ? 1 : 0);
        /* A second final is a refusal **with a reason**: the flag the first one set. */
        sayn("ctx.final.second", EVP_DigestFinal_ex(c, out, &outl));
        printf("ctx.final.second.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        say_ctx_activity("ctx.activity.after_final");

        /* -- `EVP_DigestFinal` is the destructive one: it finalises and then resets -- */
        EVP_DigestInit_ex(c, cmd, NULL);
        EVP_DigestUpdate(c, "abcd", 4);
        memset(out, 0xEE, sizeof out);
        sayn("ctx.destructive_final", EVP_DigestFinal(c, out, &outl));
        sayn("ctx.destructive_final.outl", (long long) outl);
        printf("ctx.destructive_final.reqdigest_null_after=%d\n",
               EVP_MD_CTX_get0_md(c) == NULL ? 1 : 0);
        say_ctx_activity("ctx.activity.after_destructive_final");

        /* -- the copy, which duplicates the algorithm context rather than sharing it -- */
        EVP_DigestInit_ex(c, cmd, NULL);
        EVP_DigestUpdate(c, "abcd", 4);
        copyc = EVP_MD_CTX_new();
        sayn("ctx.copy_ex", EVP_MD_CTX_copy_ex(copyc, c));
        printf("ctx.copy_ex.distinct=%d\n", copyc != c ? 1 : 0);
        printf("ctx.copy_ex.reqdigest_is_method=%d\n",
               EVP_MD_CTX_get0_md(copyc) == cmd ? 1 : 0);
        say_ctx_activity("ctx.activity.after_copy");
        /* Both contexts finalise to the same bytes; the copy took its own snapshot. */
        memset(out, 0xEE, sizeof out);
        sayn("ctx.copy_ex.final", EVP_DigestFinal_ex(copyc, out, &outl));
        sayn("ctx.copy_ex.outl", (long long) outl);
        sayn("ctx.copy_ex.byte0", out[0]);
        sayn("ctx.copy_ex.byte1", out[1]);
        memset(out, 0xEE, sizeof out);
        sayn("ctx.copy_ex.original_final", EVP_DigestFinal_ex(c, out, &outl));
        sayn("ctx.copy_ex.original_byte0", out[0]);
        sayn("ctx.copy_ex.original_byte1", out[1]);

        dupc = EVP_MD_CTX_dup(c);
        sayp("ctx.dup", dupc);
        printf("ctx.dup.distinct=%d\n", dupc != c ? 1 : 0);
        printf("ctx.dup.reqdigest_is_method=%d\n",
               dupc != NULL && EVP_MD_CTX_get0_md(dupc) == cmd ? 1 : 0);
        say_ctx_activity("ctx.activity.after_dup");
        sayn("ctx.reset", EVP_MD_CTX_reset(copyc));
        printf("ctx.reset.reqdigest_null=%d\n", EVP_MD_CTX_get0_md(copyc) == NULL ? 1 : 0);
        say_ctx_activity("ctx.activity.after_reset");
        EVP_MD_CTX_free(dupc);
        EVP_MD_CTX_free(copyc);

        /* -- the ctrl commands: two that *set* a parameter and one that *gets* one -- */
        sayn("ctx.ctrl.xoflen", EVP_MD_CTX_ctrl(c, EVP_MD_CTRL_XOF_LEN, 24, NULL));
        memset(micalg, 0, sizeof micalg);
        sayn("ctx.ctrl.micalg", EVP_MD_CTX_ctrl(c, EVP_MD_CTRL_MICALG, sizeof micalg, micalg));
        says("ctx.ctrl.micalg.text", micalg);
        sayn("ctx.ctrl.ssl3_ms", EVP_MD_CTX_ctrl(c, EVP_CTRL_SSL3_MASTER_SECRET, 4, micalg));
        /* No arm for this one and no error either: an unsupported command is not a failure. */
        sayn("ctx.ctrl.unknown", EVP_MD_CTX_ctrl(c, 0x1234, 0, NULL));
        say_ctx_activity("ctx.activity.after_ctrl");

        /* -- the XOF path: one shot, and then the repeatable read -- */
        EVP_DigestInit_ex(c, cmd, NULL);
        EVP_DigestUpdate(c, "abcd", 4);
        memset(out, 0xEE, sizeof out);
        sayn("ctx.final_xof.return", EVP_DigestFinalXOF(c, out, 24));
        sayn("ctx.final_xof.byte0", out[0]);
        sayn("ctx.final_xof.byte1", out[1]);
        sayn("ctx.final_xof.byte23", out[23]);
        /* The one-shot XOF set `FINALISED`, so the next squeeze is the *repeatable* path and is
         * not gated by it -- which is the whole difference between the two entry points. */
        memset(out, 0xEE, sizeof out);
        sayn("ctx.squeeze.first", EVP_DigestSqueeze(c, out, 24));
        sayn("ctx.squeeze.first.byte0", out[0]);
        memset(out, 0xEE, sizeof out);
        sayn("ctx.squeeze.second", EVP_DigestSqueeze(c, out, 24));
        sayn("ctx.squeeze.second.byte0", out[0]);
        say_ctx_activity("ctx.activity.after_squeeze");

        /* A method with five structural functions has no `dsqueeze`, and that is a **refusal with
         * its own reason** -- `EVP_R_METHOD_NOT_SUPPORTED` rather than a silent zero. */
        if (cmd5 != NULL) {
            EVP_MD_CTX *c5 = EVP_MD_CTX_new();
            sayn("ctx5.init", EVP_DigestInit_ex(c5, cmd5, NULL));
            sayn("ctx5.context_size", EVP_MD_CTX_get_size_ex(c5));
            memset(out, 0xEE, sizeof out);
            sayn("ctx5.squeeze", EVP_DigestSqueeze(c5, out, 24));
            printf("ctx5.squeeze.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            EVP_MD_CTX_free(c5);
        }

        /* -- the direct parameter entry points, which is the surface the ctrl commands sit on -- */
        {
            OSSL_PARAM p[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
            xoflen = 20;
            p[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &xoflen);
            sayn("ctx.set_params", EVP_MD_CTX_set_params(c, p));
            sayn("ctx.get_params", EVP_MD_CTX_get_params(c, p));
            sayn("ctx.get_params.xoflen", (long long) xoflen);
            say_ctx_activity("ctx.activity.after_params");
        }

        /* -- the two one-shots, which are the whole reason a consumer uses this at all -- */
        memset(out, 0xEE, sizeof out);
        sayn("ctx.oneshot.return", EVP_Digest("abcd", 4, out, &outl, cmd, NULL));
        sayn("ctx.oneshot.outl", (long long) outl);
        sayn("ctx.oneshot.byte0", out[0]);
        sayn("ctx.oneshot.byte1", out[1]);
        say_ctx_activity("ctx.activity.after_oneshot");
        {
            size_t qlen = 0;
            memset(out, 0xEE, sizeof out);
            sayn("ctx.q_digest.return",
                 EVP_Q_digest(ctx, "court-md-ctx", NULL, "abcd", 4, out, &qlen));
            sayn("ctx.q_digest.len", (long long) qlen);
            sayn("ctx.q_digest.byte0", out[0]);
            say_ctx_activity("ctx.activity.after_q_digest");
        }

        /* -- the pcontext seam and the flag word, on a real context -- */
        EVP_MD_CTX_set_pkey_ctx(c, NULL);
        printf("ctx.pkey.after_null_is_null=%d\n", EVP_MD_CTX_get_pkey_ctx(c) == NULL ? 1 : 0);
        /* `EVP_MD_CTX_FLAG_FINALISED` is in `include/crypto/evp.h`, which is not installed, so a
         * consumer passes the bare value -- the same choice the index numbers above make. */
        printf("ctx.flags.initial=%d\n", EVP_MD_CTX_test_flags(c, 0x0800));
        EVP_MD_CTX_set_flags(c, EVP_MD_CTX_FLAG_NO_INIT);
        printf("ctx.flags.after_set=%d\n", EVP_MD_CTX_test_flags(c, EVP_MD_CTX_FLAG_NO_INIT));
        EVP_MD_CTX_clear_flags(c, EVP_MD_CTX_FLAG_NO_INIT);
        printf("ctx.flags.after_clear=%d\n", EVP_MD_CTX_test_flags(c, EVP_MD_CTX_FLAG_NO_INIT));
        EVP_MD_CTX_set_update_fn(c, NULL);
        printf("ctx.update_fn.after_null_set_null=%d\n", EVP_MD_CTX_update_fn(c) == NULL ? 1 : 0);
        say_ctx_activity("ctx.activity.final");

        EVP_MD_CTX_free(c);
        say_ctx_activity("ctx.activity.after_free");
        EVP_MD_free(cmd);
        EVP_MD_free(cmd5);
        ERR_clear_error();

        /*
         * The four boundaries a probe cannot compare, each measured against the authority in a
         * process of its own and each therefore printed rather than skipped --
         * `docs/SECURITY_DIVERGENCE_POLICY.md` D-MD-NULL-CALLBACK-1 and D-MD-DOALL-NULL-1.
         *
         * Each of the three NULL-callback calls is reachable through the documented entry points
         * below it, so a reader of this transcript should see the edge rather than infer from the
         * silence that it was overlooked.
         */
        printf("ctx.meth_no_init=NOT_MEASURED_AUTHORITY_FAULTS\n");
        printf("ctx.meth_no_final=NOT_MEASURED_AUTHORITY_FAULTS\n");
        printf("ctx.one_shot_only_newctx=NOT_MEASURED_AUTHORITY_FAULTS\n");
        printf("ctx.do_all_null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");
    }

    /* One unload takes the count back to 1, where the authority answers 1 without removing
     * anything; the second reaches `provider_remove_store_methods`, and that reaches
     * `evp_method_store_remove_all_provided`. Both are compared by return code. */
    sayn("unload.first", OSSL_PROVIDER_unload(p));
    sayn("unload.last", OSSL_PROVIDER_unload(q));

    /*
     * ---- the same call with nothing loaded, which is where the *reason* is observable ----
     *
     * `inner_evp_generic_fetch` computes `unsupported` as "the constructor was never entered"
     * and then picks between two reasons on it:
     *
     *     int code = unsupported ? ERR_R_UNSUPPORTED : ERR_R_FETCH_FAILED;
     *     ERR_raise_data(ERR_LIB_EVP, code, "%s, Algorithm (%s : %d), Properties (%s)", ...);
     *
     * Both arms build the **same message**, so the code is the entire observation: a
     * transcription that used one arm for both -- or that read the constant off the neighbouring
     * `ERR_raise_data` at `evp_fetch.c:352`, which is the *other* arm and has a reason of its
     * own -- raises a plausible error that no other line in any transcript would contradict.
     * This is the observation that caught exactly that in the candidate, and it is worth its own
     * block rather than being a side effect of the order two other blocks happen to be in.
     *
     * The name is still in no namemap entry a provider published, so the answer is NULL and the
     * reason is the "nothing offers this" one -- not merely "NULL", which both arms agree on.
     */
    {
        EVP_MD *md = EVP_MD_fetch(ctx, "court-md", NULL);

        printf("fetch.unloaded_null=%d\n", md == NULL ? 1 : 0);
        printf("fetch.unloaded.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        EVP_MD_free(md);
    }

    /*
     * And the store is still the same object, still non-NULL, and still usable afterwards -- and
     * the queue is empty here on purpose: this line is about the *store*, and a leftover error
     * from the block above would make it about the fetch instead, which is the class of accident
     * that hid the reason-code divergence until the block was given a name.
     */
    /*
     * ---- 7.3d: the `EVP_MD` accessors, the method constructors, and `EVP_md_null` ----
     *
     * The accessors are read on a *fetched* method, which is the only kind whose provider half is
     * live; the constructors are exercised on a method built by hand, which is the only kind whose
     * legacy half is; and `EVP_md_null` is the one global with neither.
     */
    {
        EVP_MD *fetched = EVP_MD_fetch(ctx, "court-md", NULL);
        EVP_MD *byhand;
        const EVP_MD *global;

        sayp("md.fetch.for_accessors", fetched);
        if (fetched != NULL) {
            const char *desc = EVP_MD_get0_description(fetched);

            printf("md.description_matches=%d\n",
                   desc != NULL && strcmp(desc, "court digest") == 0 ? 1 : 0);
            sayp("md.provider", (const void *) EVP_MD_get0_provider(fetched));
            sayn("md.flags", (long long) EVP_MD_get_flags(fetched));
            sayn("md.pkey_type", EVP_MD_get_pkey_type(fetched));
            sayn("md.xof", EVP_MD_xof(fetched));
            sayn("md.is_a.name", EVP_MD_is_a(fetched, "court-md"));
            sayn("md.is_a.alias", EVP_MD_is_a(fetched, "courtmd"));
            sayn("md.is_a.other", EVP_MD_is_a(fetched, "sha256"));
            sayp("md.gettable_params", (const void *) EVP_MD_gettable_params(fetched));
            sayp("md.gettable_ctx_params", (const void *) EVP_MD_gettable_ctx_params(fetched));
            sayp("md.settable_ctx_params", (const void *) EVP_MD_settable_ctx_params(fetched));
            {
                size_t sz = 0;
                OSSL_PARAM p[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

                p[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &sz);
                sayn("md.get_params.ret", EVP_MD_get_params(fetched, p));
                sayn("md.get_params.size", (long long) sz);
            }
            {
                struct name_seen s;

                memset(&s, 0, sizeof s);
                sayn("md.names_do_all.ret", EVP_MD_names_do_all(fetched, name_visitor, &s));
                sayn("md.names.count", s.count);
                sayn("md.names.saw_identity", s.saw_identity);
                sayn("md.names.saw_alias", s.saw_alias);
            }
            EVP_MD_free(fetched);
        }

        byhand = EVP_MD_meth_new(4, 5);
        sayp("md.meth.new", byhand);
        if (byhand != NULL) {
            sayn("md.meth.new.type", EVP_MD_get_type(byhand));
            sayn("md.meth.new.pkey_type", EVP_MD_get_pkey_type(byhand));
            sayn("md.meth.new.provider_null", EVP_MD_get0_provider(byhand) == NULL ? 1 : 0);
            sayn("md.meth.set_result_size.first", EVP_MD_meth_set_result_size(byhand, 32));
            sayn("md.meth.set_result_size.second", EVP_MD_meth_set_result_size(byhand, 64));
            sayn("md.meth.get_result_size", EVP_MD_meth_get_result_size(byhand));
            sayn("md.meth.set_input_blocksize", EVP_MD_meth_set_input_blocksize(byhand, 64));
            sayn("md.meth.get_input_blocksize", EVP_MD_meth_get_input_blocksize(byhand));
            sayn("md.meth.set_app_datasize", EVP_MD_meth_set_app_datasize(byhand, 16));
            sayn("md.meth.get_app_datasize", EVP_MD_meth_get_app_datasize(byhand));
            sayn("md.meth.set_flags.first", EVP_MD_meth_set_flags(byhand, EVP_MD_FLAG_XOF));
            sayn("md.meth.set_flags.second", EVP_MD_meth_set_flags(byhand, 0));
            sayn("md.meth.get_flags", (long long) EVP_MD_meth_get_flags(byhand));
            sayn("md.meth.xof_after_set", EVP_MD_xof(byhand));
            sayn("md.meth.set_init", EVP_MD_meth_set_init(byhand, meth_md_init));
            sayn("md.meth.set_init.second", EVP_MD_meth_set_init(byhand, meth_md_init));
            printf("md.meth.get_init_matches=%d\n",
                   EVP_MD_meth_get_init(byhand) == meth_md_init ? 1 : 0);
            sayn("md.meth.get_update_null", EVP_MD_meth_get_update(byhand) == NULL ? 1 : 0);
            sayn("md.meth.get_final_null", EVP_MD_meth_get_final(byhand) == NULL ? 1 : 0);
            sayn("md.meth.get_copy_null", EVP_MD_meth_get_copy(byhand) == NULL ? 1 : 0);
            sayn("md.meth.get_cleanup_null", EVP_MD_meth_get_cleanup(byhand) == NULL ? 1 : 0);
            sayn("md.meth.get_ctrl_null", EVP_MD_meth_get_ctrl(byhand) == NULL ? 1 : 0);

            /*
             * ---- the **legacy** arm of the initialise, through a context ----
             *
             * This is the one place the other half of `evp_md_init_internal` is reachable from a
             * probe. The method's origin is `EVP_ORIG_METH`, so the legacy arm is taken whatever
             * else is true; its `init` was set above, so the call is made and the counter moves;
             * and its `app_datasize` is 16, so the context allocated a data block for it -- which
             * is the difference between the two halves of the object that the accessors can see.
             *
             * Its `update` is NULL, so `EVP_DigestUpdate` refuses rather than faulting (the
             * authority tests that pointer), and its `final` is NULL, which the authority does
             * **not** test -- so the final is one of the four boundaries printed below instead of
             * executed.
             */
            {
                EVP_MD_CTX *mc = EVP_MD_CTX_new();

                printf("md.meth.ctx.md_data_null_before=%d\n",
                       EVP_MD_CTX_get0_md_data(mc) == NULL ? 1 : 0);
                sayn("md.meth.ctx.init", EVP_DigestInit_ex(mc, byhand, NULL));
                sayn("md.meth.ctx.init_calls", meth_init_calls);
                printf("md.meth.ctx.md_data_nonnull=%d\n",
                       EVP_MD_CTX_get0_md_data(mc) != NULL ? 1 : 0);
                printf("md.meth.ctx.reqdigest_is_method=%d\n",
                       EVP_MD_CTX_get0_md(mc) == byhand ? 1 : 0);
                sayn("md.meth.ctx.size", EVP_MD_CTX_get_size_ex(mc));
                /* `update` is copied from the method, and the method has none. */
                printf("md.meth.ctx.update_null=%d\n", EVP_MD_CTX_update_fn(mc) == NULL ? 1 : 0);
                sayn("md.meth.ctx.update", EVP_DigestUpdate(mc, "ab", 2));
                /* A re-init on the same method keeps the block it already has. */
                sayn("md.meth.ctx.reinit", EVP_DigestInit_ex(mc, byhand, NULL));
                sayn("md.meth.ctx.reinit_calls", meth_init_calls);
                /* A NULL `type` means "the method this context already has", which the legacy arm
                 * reads back out of `ctx->digest` rather than re-resolving. */
                sayn("md.meth.ctx.reinit_null_type", EVP_DigestInit_ex(mc, NULL, NULL));
                sayn("md.meth.ctx.reinit_null_type_calls", meth_init_calls);
                /* And a final would be the third boundary; measured, not executed. */
                printf("md.meth.ctx.final=NOT_MEASURED_AUTHORITY_FAULTS\n");
                EVP_MD_CTX_free(mc);
            }

            EVP_MD_free(byhand);
            sayn("md.meth.after_public_free.result_size", EVP_MD_meth_get_result_size(byhand));
            {
                EVP_MD *dup = EVP_MD_fetch(ctx, "court-md", NULL);

                sayp("md.meth.dup_of_provider", dup);
                EVP_MD_meth_free(dup);
                sayn("md.meth.fetched_survives_meth_free", EVP_MD_get_size(dup));
                EVP_MD_free(dup);
            }
            EVP_MD_meth_free(byhand);
        }

        global = EVP_md_null();
        sayp("md_null.nonnull", (const void *) global);
        if (global != NULL) {
            sayn("md_null.type", EVP_MD_get_type(global));
            sayn("md_null.block_size", EVP_MD_get_block_size(global));
            sayn("md_null.size", EVP_MD_get_size(global));
            sayn("md_null.flags", (long long) EVP_MD_get_flags(global));
            sayn("md_null.xof", EVP_MD_xof(global));
            sayn("md_null.provider_null", EVP_MD_get0_provider(global) == NULL ? 1 : 0);
            printf("md_null.stable=%d\n", EVP_md_null() == EVP_md_null() ? 1 : 0);
            sayn("md_null.up_ref", EVP_MD_up_ref((EVP_MD *) global));
            EVP_MD_free((EVP_MD *) global);
            sayn("md_null.block_size_after_free", EVP_MD_get_block_size(global));
        }

        /* The accessors' NULL arms, and the two that deliberately have none are absent. */
        sayn("md.null.xof", EVP_MD_xof(NULL));
        sayn("md.null.is_a", EVP_MD_is_a(NULL, "court-md"));
        sayp("md.null.gettable_params", (const void *) EVP_MD_gettable_params(NULL));
        sayp("md.null.gettable_ctx_params", (const void *) EVP_MD_gettable_ctx_params(NULL));
        sayp("md.null.settable_ctx_params", (const void *) EVP_MD_settable_ctx_params(NULL));
        sayn("md.null.get_params", EVP_MD_get_params(NULL, NULL));
    }
    ERR_clear_error();
    printf("after.store.stable=%d err=%lu\n",
           store == OSSL_LIB_CTX_get_data(ctx, IDX_EVP_METHOD_STORE) ? 1 : 0,
           ERR_peek_error());
    ERR_clear_error();
    sayp("after.store", OSSL_LIB_CTX_get_data(ctx, IDX_EVP_METHOD_STORE));

    OSSL_LIB_CTX_free(other);
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
