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
 * a consumer can reach is `OSSL_LIB_CTX_get_data`, and what a consumer will reach once 7.2
 * lands is `EVP_MD_fetch` and its siblings.
 *
 * So this probe observes the store **as an object in the index table** plus the two export
 * paths that delegate into it, and says so rather than implying more:
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
 *
 * What 7.2 adds, and why the name is right anyway
 * ----------------------------------------------
 * The plan's 7.2 row **extends this court**, and it will not be an extension of a different
 * kind of observation: when `EVP_MD_fetch` and `evp_generic_fetch` exist, the same probe gains
 * a resolver -- a provider that publishes an algorithm, a query that selects it, a query that
 * *rejects* it -- and the fetch path becomes observable the way every other court observes
 * its subject. Until then this is what there is, and the alternative was worse: naming
 * `RT-FETCH` without a probe would leave the stratum's one new observable object uncounted,
 * which is the D49/D51 class this project keeps removing.
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
 *     is a real observation and is available there, and it becomes *interesting* rather than
 *     merely present once a fetch can be run against a child's scope -- which is 7.2.
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

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    (void) operation_id;
    /* An empty operation table, which is what makes this provider's only relevance the fact
     * that it can be loaded and unloaded: `ossl_provider_query_operation` answers NULL, and the
     * algorithm walk therefore visits nothing. */
    *no_cache = 0;
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

    /* One unload takes the count back to 1, where the authority answers 1 without removing
     * anything; the second reaches `provider_remove_store_methods`, and that reaches
     * `evp_method_store_remove_all_provided`. Both are compared by return code. */
    sayn("unload.first", OSSL_PROVIDER_unload(p));
    sayn("unload.last", OSSL_PROVIDER_unload(q));

    /* And the store is still the same object, still non-NULL, and still usable afterwards. */
    printf("after.store.stable=%d err=%lu\n",
           store == OSSL_LIB_CTX_get_data(ctx, IDX_EVP_METHOD_STORE) ? 1 : 0,
           ERR_peek_error());
    ERR_clear_error();
    sayp("after.store", OSSL_LIB_CTX_get_data(ctx, IDX_EVP_METHOD_STORE));

    OSSL_LIB_CTX_free(other);
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
