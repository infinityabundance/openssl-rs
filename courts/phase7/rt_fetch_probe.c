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
 *     child's scope needs a *provider* published into that child, which is `RT-PROVIDER-3P`'s
 *     to build, not this court's to approximate.
 *
 * Addresses are never printed. Every observation is a relation between two pointers this probe
 * holds (`same` / `different`), a presence answer (`NULL` / `nonnull`), or a return code,
 * because the two libraries' addresses are not comparable and printing one would compare the
 * probe's heap layout rather than the library's behaviour.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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
 * something to answer. It is never called by this probe: `EVP_MD_CTX` is 7.3d's second half. */
static int meth_md_init(EVP_MD_CTX *ctx)
{
    (void) ctx;
    return 1;
}

static const OSSL_DISPATCH court_digest_fns[] = {
    { OSSL_FUNC_DIGEST_DIGEST, (void (*)(void)) court_digest },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) court_get_params },
    { 0, NULL }
};

/* The published name list: three aliases, the first of which is the identity. The provider's
 * property definition is what the *negative* selection below rejects. */
static const OSSL_ALGORITHM court_digests[] = {
    { "court-md:Court-MD:courtmd", "provider=court", court_digest_fns, "court digest" },
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
