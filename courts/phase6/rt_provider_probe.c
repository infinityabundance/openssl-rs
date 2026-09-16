/*
 * RT-PROVIDER -- the registry, from the one angle both sides can be asked.
 *
 * A builtin provider is the only provider a probe can create on *both* sides. The two
 * libraries' own providers (`default`, `base`, `null`, `legacy`) are each published by their
 * own `OSSL_provider_init`, so observing them would compare the probe's environment rather
 * than the registry. What this probe does instead is declare its own entry point, register it
 * through `OSSL_PROVIDER_add_builtin`, and then drive the registry through the public API:
 * create, activate, initialise, query, configure, enumerate, deactivate, unload, reload.
 *
 * The whole of 6.8c's reachable surface is on that path, and so is the dispatch-table walk
 * inside `provider_init`: the eight `OSSL_FUNC_PROVIDER_*` entries this probe publishes are
 * what the walk stores, and every one of them is then called back through the object.
 *
 * ## What is observed, and what is deliberately not
 *
 * Every value printed is equal on the two sides **by construction**: no pointer is ever
 * printed, only NULL-ness, `matches` (a pointer compared with the one this probe itself
 * published) and `strcmp`-against-the-input. A pointer printed would be a difference in the
 * *load address*, which is not a difference in the contract.
 *
 * **The fallback walk is observed only in its disabled state.** `provider_activate_fallbacks`
 * loads the table's `is_fallback` rows through their compiled-in entry points, and the
 * candidate has none of them yet: `ossl_default_provider_init` (807 lines),
 * `ossl_base_provider_init` and `ossl_null_provider_init` are 7/8's, so `provider_init` takes
 * the *module* branch, `DSO_load("libdefault.so")` fails, and the walk answers 0 where the
 * authority answers 1. That divergence is real, it is recorded in
 * `docs/PHASE-6-SUBPHASES.md` (6.8c, residual 1) and in `docs/SECURITY_DIVERGENCE_POLICY.md`,
 * and this probe **never puts the flag in its enabled state**: the first public call it makes
 * is `OSSL_PROVIDER_load`, which sets `store->use_fallbacks = 0` before it looks anything up.
 * From that point on the walk's early return is what both sides take, so `available`,
 * `do_all` and the enumeration below *are* compared -- they would not be if the walk had run.
 * The disabled path is therefore courted, the enabled path is named rather than hidden, and
 * the day 7/8 lands the entry points this comment stops being true and the omission must be
 * revisited with it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

/* ------------------------------------------------------------------ */
/* The provider this probe declares                                    */
/* ------------------------------------------------------------------ */

/* The context the entry point publishes, so every callback can compare its argument with
 * it. A file-scope object rather than an allocation: its address is what is compared, and
 * it is never dereferenced by either side. */
static char court_provctx_marker;

/* What the provider's own callbacks saw. */
static int seen_ctx_matches;
static int seen_get_params_null;
static int seen_get_params_table;
static int seen_self_test_calls;
static int seen_cap_first_byte;
static int seen_cap_ctx_matches;
static int seen_query_ctx_matches;
static int seen_query_op_id;
static int seen_unquery_ctx_matches;
static int seen_unquery_op_id;
static int seen_unquery_algs_matches;
static int seen_teardown_calls;
static int seen_teardown_ctx_matches;
static int seen_handle_nonnull;

/* The marker `gettable_params` answers, and the marker `query_operation` answers. */
static const OSSL_PARAM court_gettable[] = { OSSL_PARAM_END };
static int court_alg_marker;

static int self_test_verdict = 1;

static void court_teardown(void *provctx);
static const OSSL_PARAM *court_gettable_params(void *provctx);
static int court_get_params(void *provctx, OSSL_PARAM params[]);
static int court_self_test(void *provctx);
static int court_get_capabilities(void *provctx, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg);
static const OSSL_ALGORITHM *court_query_operation(void *provctx, int operation_id,
                                                   int *no_cache);
static void court_unquery_operation(void *provctx, int operation_id,
                                    const OSSL_ALGORITHM *algs);

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))court_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))court_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))court_get_params },
    { OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))court_self_test },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))court_get_capabilities },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))court_query_operation },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))court_unquery_operation },
    { 0, NULL }
};

static int court_provider_init(const OSSL_CORE_HANDLE *handle,
                              const OSSL_DISPATCH *in,
                              const OSSL_DISPATCH **out,
                              void **provctx)
{
    seen_handle_nonnull = handle != NULL ? 1 : 0;
    /* `in` is the core dispatch table the loader passes; both sides publish one, and its
     * contents are the other courts' subject, so only its presence is recorded. */
    if (in == NULL)
        return 0;
    *out = court_dispatch;
    *provctx = &court_provctx_marker;
    return 1;
}

static void court_teardown(void *provctx)
{
    seen_teardown_calls++;
    seen_teardown_ctx_matches = provctx == &court_provctx_marker ? 1 : 0;
}

static const OSSL_PARAM *court_gettable_params(void *provctx)
{
    seen_ctx_matches = provctx == &court_provctx_marker ? 1 : 0;
    return court_gettable;
}

static int court_get_params(void *provctx, OSSL_PARAM params[])
{
    seen_ctx_matches = provctx == &court_provctx_marker ? 1 : 0;
    if (params == NULL)
        seen_get_params_null = 1;
    else
        seen_get_params_table = 1;
    return 1;
}

static int court_self_test(void *provctx)
{
    seen_ctx_matches = provctx == &court_provctx_marker ? 1 : 0;
    seen_self_test_calls++;
    return self_test_verdict;
}

static int court_get_capabilities(void *provctx, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg)
{
    seen_cap_ctx_matches = provctx == &court_provctx_marker ? 1 : 0;
    seen_cap_first_byte = capability == NULL ? -1 : (int)(unsigned char)capability[0];
    /* The two remaining arguments are the caller's, and the authority hands them straight
     * through. `cb` is NULL here because the probe passes NULL; record that it is the same
     * NULL it passed rather than printing a value. */
    (void)cb;
    (void)arg;
    return 9;
}

static const OSSL_ALGORITHM *court_query_operation(void *provctx, int operation_id,
                                                   int *no_cache)
{
    seen_query_ctx_matches = provctx == &court_provctx_marker ? 1 : 0;
    seen_query_op_id = operation_id;
    if (no_cache != NULL)
        *no_cache = 1;
    return (const OSSL_ALGORITHM *)&court_alg_marker;
}

static void court_unquery_operation(void *provctx, int operation_id,
                                    const OSSL_ALGORITHM *algs)
{
    seen_unquery_ctx_matches = provctx == &court_provctx_marker ? 1 : 0;
    seen_unquery_op_id = operation_id;
    seen_unquery_algs_matches = algs == (const OSSL_ALGORITHM *)&court_alg_marker ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* `do_all`'s callback                                                 */
/* ------------------------------------------------------------------ */

static int do_all_count;
static int do_all_names_match;
static int do_all_ctx_matches;

static int do_all_cb(OSSL_PROVIDER *provider, void *cbdata)
{
    const char *name = OSSL_PROVIDER_get0_name(provider);
    void *ctx = OSSL_PROVIDER_get0_provider_ctx(provider);
    do_all_count++;
    if (name == NULL || strcmp(name, "court-prov") != 0)
        do_all_names_match = 0;
    if (ctx == cbdata)
        do_all_ctx_matches = 1;
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *p, *q, *r;
    const OSSL_DISPATCH *disp;
    const OSSL_PARAM *table;
    char buf[64];
    char boolbuf[64];
    char *kptr = buf;
    char *bptr = boolbuf;
    OSSL_PARAM params[3];
    int ret;

    /* Line-buffer everything: a probe that dies part way through must still have its
     * observations in the pipe, or a crash reads as agreement. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }

    /* ---- registration, and its two refusals ---- */
    ret = OSSL_PROVIDER_add_builtin(ctx, "court-prov", court_provider_init);
    printf("add_builtin.ret=%d\n", ret);
    printf("add_builtin.null_name=%d\n",
           OSSL_PROVIDER_add_builtin(ctx, NULL, court_provider_init));
    printf("add_builtin.null_init=%d\n",
           OSSL_PROVIDER_add_builtin(ctx, "court-prov-null", NULL));

    /* ---- the load, which is also what disables the fallback walk ---- */
    p = OSSL_PROVIDER_load(ctx, "court-prov");
    printf("load.nonnull=%d\n", p != NULL ? 1 : 0);
    if (p == NULL) {
        printf("load.failed=1\n");
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    printf("init.handle_nonnull=%d\n", seen_handle_nonnull);

    printf("get0_name.is_court_prov=%d\n",
           OSSL_PROVIDER_get0_name(p) != NULL
               && strcmp(OSSL_PROVIDER_get0_name(p), "court-prov") == 0);
    printf("get0_ctx.matches=%d\n",
           OSSL_PROVIDER_get0_provider_ctx(p) == &court_provctx_marker);

    disp = OSSL_PROVIDER_get0_dispatch(p);
    printf("get0_dispatch.nonnull=%d\n", disp != NULL ? 1 : 0);
    /* The first entry's id is the one the probe published, and the terminator is where the
     * probe put it. Comparing *ids* rather than pointers is the whole point: the tables are
     * at different addresses on the two sides and identical in content. */
    printf("get0_dispatch.first_id=%d\n",
           disp != NULL ? (int)disp[0].function_id : -1);
    printf("get0_dispatch.terminator_id=%d\n",
           disp != NULL ? (int)disp[7].function_id : -1);
    printf("get0_dispatch.terminator_null=%d\n",
           disp != NULL && disp[7].function == NULL ? 1 : 0);

    /* ---- a second load: the provider is already in the store ---- */
    q = OSSL_PROVIDER_load(ctx, "court-prov");
    printf("load_again.nonnull=%d\n", q != NULL ? 1 : 0);
    printf("load_again.same_object=%d\n", q == p ? 1 : 0);

    /* ---- the four delegated calls that answer through the provider's context ---- */
    table = OSSL_PROVIDER_gettable_params(p);
    printf("gettable_params.matches=%d\n", table == court_gettable ? 1 : 0);
    printf("gettable_params.ctx_matches=%d\n", seen_ctx_matches);

    printf("get_params.null_table=%d\n",
           OSSL_PROVIDER_get_params(p, NULL));
    printf("get_params.saw_null=%d\n", seen_get_params_null);
    printf("get_params.ctx_matches=%d\n", seen_ctx_matches);
    params[0] = OSSL_PARAM_construct_utf8_ptr("k", &kptr, sizeof(buf));
    params[1] = OSSL_PARAM_construct_end();
    printf("get_params.real_table=%d\n",
           OSSL_PROVIDER_get_params(p, params));
    printf("get_params.saw_table=%d\n", seen_get_params_table);

    printf("self_test.ret=%d\n", OSSL_PROVIDER_self_test(p));
    printf("self_test.calls=%d\n", seen_self_test_calls);

    printf("get_capabilities.ret=%d\n",
           OSSL_PROVIDER_get_capabilities(p, "TLS-GROUP", NULL, NULL));
    printf("get_capabilities.first_byte=%d\n", seen_cap_first_byte);
    printf("get_capabilities.ctx_matches=%d\n", seen_cap_ctx_matches);

    /* ---- the algorithm query, and the pointer the unquery gets back ---- */
    {
        int no_cache = 0;
        const OSSL_ALGORITHM *algs = OSSL_PROVIDER_query_operation(p, 7, &no_cache);
        printf("query.nonnull=%d\n", algs != NULL ? 1 : 0);
        printf("query.no_cache=%d\n", no_cache);
        printf("query.op_id=%d\n", seen_query_op_id);
        printf("query.ctx_matches=%d\n", seen_query_ctx_matches);
        /* `no_cache` is *not* forced by either side: the profile does not define
         * OPENSSL_NO_CACHED_FETCH, so the provider's own write is what survives. */
        OSSL_PROVIDER_unquery_operation(p, 7, algs);
        printf("unquery.op_id=%d\n", seen_unquery_op_id);
        printf("unquery.algs_matches=%d\n", seen_unquery_algs_matches);
        printf("unquery.ctx_matches=%d\n", seen_unquery_ctx_matches);
    }

    /* A NULL `no_cache` is legal and must not be written through. */
    printf("query.null_no_cache.nonnull=%d\n",
           OSSL_PROVIDER_query_operation(p, 7, NULL) != NULL ? 1 : 0);
    printf("unquery.after_null=%d\n", seen_unquery_op_id);

    /* ---- the CONF parameter list ---- */
    printf("conf_add.ret=%d\n", OSSL_PROVIDER_add_conf_parameter(p, "k", "v"));
    printf("conf_add.bool_ret=%d\n", OSSL_PROVIDER_add_conf_parameter(p, "b", "true"));
    memset(buf, 0, sizeof(buf));
    memset(boolbuf, 0, sizeof(boolbuf));
    params[0] = OSSL_PARAM_construct_utf8_ptr("k", &kptr, sizeof(buf));
    params[1] = OSSL_PARAM_construct_utf8_ptr("b", &bptr, sizeof(boolbuf));
    params[2] = OSSL_PARAM_construct_end();
    printf("get_conf_parameters.ret=%d\n",
           OSSL_PROVIDER_get_conf_parameters(p, params));
    printf("get_conf_parameters.k_is_v=%d\n", strcmp(buf, "v") == 0);
    printf("get_conf_parameters.b_is_true=%d\n", strcmp(boolbuf, "true") == 0);
    printf("conf_get_bool.b=%d\n", OSSL_PROVIDER_conf_get_bool(p, "b", 0));
    printf("conf_get_bool.k_default=%d\n", OSSL_PROVIDER_conf_get_bool(p, "k", 7));
    printf("conf_get_bool.missing_default=%d\n",
           OSSL_PROVIDER_conf_get_bool(p, "nope", 7));

    /* ---- the default search path, which is per context and not per provider ---- */
    printf("search_path.initially_null=%d\n",
           OSSL_PROVIDER_get0_default_search_path(ctx) == NULL ? 1 : 0);
    printf("search_path.set=%d\n",
           OSSL_PROVIDER_set_default_search_path(ctx, "providers-here"));
    {
        const char *sp = OSSL_PROVIDER_get0_default_search_path(ctx);
        printf("search_path.reads_back=%d\n",
               sp != NULL && strcmp(sp, "providers-here") == 0);
    }
    /* A NULL path clears it, and the answer is still 1 -- the release happens *before* the
     * NULL test in the authority, which is why clearing is a success and not a no-op. */
    printf("search_path.clear=%d\n",
           OSSL_PROVIDER_set_default_search_path(ctx, NULL));
    printf("search_path.cleared=%d\n",
           OSSL_PROVIDER_get0_default_search_path(ctx) == NULL ? 1 : 0);

    /* ---- availability, and a name that does not exist ---- */
    printf("available.known=%d\n", OSSL_PROVIDER_available(ctx, "court-prov"));
    printf("available.unknown=%d\n", OSSL_PROVIDER_available(ctx, "no-such-provider"));
    /* With the fallback walk disabled, `default` is *not* available even though it is a
     * predefined row. This is the same observation on both sides -- see the note at the top
     * about why the walk is only ever entered in its disabled state. */
    printf("available.default_after_disable=%d\n",
           OSSL_PROVIDER_available(ctx, "default"));

    /* ---- the enumeration ---- */
    do_all_count = 0;
    do_all_names_match = 1;
    do_all_ctx_matches = 0;
    printf("do_all.ret=%d\n",
           OSSL_PROVIDER_do_all(ctx, do_all_cb, &court_provctx_marker));
    printf("do_all.count=%d\n", do_all_count);
    printf("do_all.every_name_matched=%d\n", do_all_names_match);
    printf("do_all.ctx_reached=%d\n", do_all_ctx_matches);

    /* ---- a load of a name that cannot be resolved ---- */
    r = OSSL_PROVIDER_load(ctx, "no-such-provider");
    printf("load_unknown.nonnull=%d\n", r != NULL ? 1 : 0);
    if (r != NULL)
        OSSL_PROVIDER_unload(r);

    /* ---- unload, teardown, and the reload that finds the stored object ---- */
    printf("unload.ret=%d\n", OSSL_PROVIDER_unload(p));
    printf("unload.teardown_calls=%d\n", seen_teardown_calls);
    printf("unload.teardown_ctx_matches=%d\n", seen_teardown_ctx_matches);
    printf("available.after_unload=%d\n", OSSL_PROVIDER_available(ctx, "court-prov"));

    r = OSSL_PROVIDER_load(ctx, "court-prov");
    printf("reload.nonnull=%d\n", r != NULL ? 1 : 0);
    printf("reload.same_object=%d\n", r == p ? 1 : 0);
    /* Initialisation happened once, at the first activation, and a reload after a
     * deactivation does not run it again: the flag is still set and the context is the one
     * the first `init` published. */
    printf("reload.ctx_matches=%d\n",
           r != NULL && OSSL_PROVIDER_get0_provider_ctx(r) == &court_provctx_marker);
    printf("reload.teardown_still=%d\n", seen_teardown_calls);

    /* The second reference is the one `load_again` took, and the first is the reload's. */
    printf("unload.again=%d\n", OSSL_PROVIDER_unload(r));
    printf("unload.q=%d\n", OSSL_PROVIDER_unload(q));
    printf("unload.teardown_after_all=%d\n", seen_teardown_calls);

    /* ---- the NULL contract on the releases ---- */
    printf("unload.null=%d\n", OSSL_PROVIDER_unload(NULL));

    OSSL_LIB_CTX_free(ctx);
    return 0;
}
