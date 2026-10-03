/*
 * RT-PROVIDER-3P -- the provider **core** hosting a third-party provider.
 *
 * Why this court is different from every other in this stratum
 * -----------------------------------------------------------
 * `RT-PROVIDER` drives the registry through the public API and observes the objects it
 * creates. That is the registry seen from *outside*. This court is the registry seen from
 * **inside a provider**: the probe compiles an `OSSL_provider_init` into its own binary,
 * registers it with `OSSL_PROVIDER_add_builtin`, loads it, and then everything it observes is
 * what the core handed it and what the core did with what it handed back.
 *
 * That is the only way to reach the core's *provider-facing* surface at all. The dispatch
 * table a provider receives -- the four `CORE_*` entries it calls back through, the reference
 * counting pair, the child-callback pair -- is passed to `OSSL_provider_init` and to nothing
 * else. A probe that is not a provider cannot see it, so before this court the whole of that
 * surface was uncourted.
 *
 * What the probe's provider does, and why each step is an observation
 * ------------------------------------------------------------------
 * Inside `init`, in order:
 *
 *   * **walks the dispatch table it was handed**, counts the entries *outside the one
 *     deferred family* and digests their id sequence, and records which of the ids it needs
 *     are present. A core that omitted one of them would still load the provider -- it would
 *     simply fail later, inside the provider, which is the failure mode this court exists to
 *     catch. The digest is the observation that pins the table's *contents and order*: a
 *     substituted id has the same count and a different digest.
 *   * **`OSSL_FUNC_CORE_GET_LIBCTX`**: the context the provider was loaded into, compared
 *     against the one the probe passed to `OSSL_PROVIDER_load`. That comparison is the whole
 *     contract of that entry, and it is a *pointer* comparison the probe can make because it
 *     holds both pointers.
 *   * **`OSSL_FUNC_CORE_GET_PARAMS`**: `OSSL_PROV_PARAM_CORE_VERSION` and
 *     `OSSL_PROV_PARAM_CORE_PROV_NAME`, the two parameters every provider is entitled to ask
 *     for, plus a *configuration* parameter the probe set through `OSSL_PROVIDER_load_ex` and
 *     one it never set. `core_get_params` answers the first two itself and then merges the
 *     provider's configuration parameters over the same array, so the third key must come back
 *     and the fourth must be left **untouched** -- `OSSL_PARAM_modified` false, pointer still
 *     NULL. A core that answered the unset key would be indistinguishable from one that
 *     answered it correctly if the probe only asked for keys it had set, which is why the
 *     absent key is an observation rather than a negative control.
 *   * **`OSSL_FUNC_CORE_THREAD_START`**: the entry a provider uses to be told when a thread
 *     stops. The argument *order* differs between the dispatch entry and
 *     `ossl_init_thread_start`, and a transcription that transposed them would compile,
 *     because both are pointer-sized -- so the probe registers a handler and then stops the
 *     thread, and the handler's having run is the evidence.
 *   * **the `CRYPTO_*` trio**: `MALLOC`, `ZALLOC` and `FREE` through the core, with a round
 *     trip whose contents are checked. A provider must be able to allocate through the core
 *     rather than through its own allocator, because the application may have installed one.
 *   * **`OSSL_LIB_CTX_new_child`**: a child context, created *from inside* a provider's init,
 *     which is what the authority's own `provfetchtest.c` exists to demonstrate. The probe
 *     records that it is non-NULL and that slot 18 exists for it.
 *   * **the child-callback pair**: `OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB` is called with the
 *     probe's three callbacks and the child as `cbdata`, and
 *     `OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB` afterwards. What the core does with them is
 *     the observation: the registration walks the parent's already-activated providers and
 *     calls the probe's `create_cb` for each, and the deregistration removes the record.
 *
 * The lookup macro reads the *entry*, not the table
 * ------------------------------------------------
 * `OSSL_FUNC_core_get_params(in)` is `(OSSL_FUNC_core_get_params_fn *)in->function` -- it
 * casts the entry it is given, and does no lookup at all. Passing the **table base** therefore
 * hands back whatever the core happens to publish at position 0, which in this build is
 * `core_gettable_params` (`OSSL_FUNC_CORE_GETTABLE_PARAMS` == 1). The mistake compiles, because
 * every entry's `function` field has the same type; it is caught only at the call, where
 * `core_gettable_params` is invoked as `core_get_libctx` and answers a `const OSSL_PARAM *`
 * reinterpreted as a pointer, and `CRYPTO_malloc(size, file, line)` is invoked as
 * `core_gettable_params` and faults on the third argument.
 *
 * So the walk below keeps its own cursor `p` and passes `p`, while the table base is kept
 * separately and untouched -- which it must be, because `OSSL_LIB_CTX_new_child` needs the
 * base and the authority's own providers consume the cursor. `in.first_id` is printed so the
 * transcript states where the walk started, which is the id this trap turns on: the authority
 * and this candidate both publish `CORE_GETTABLE_PARAMS` (1) first, so the mistake above is
 * *deterministic* rather than intermittent, and `in.first_id` is what makes that visible in
 * the transcript instead of being a fact about the header.
 *
 * What this court deliberately does not do
 * ---------------------------------------
 * * **No `rand_*` entry count.** The authority publishes eight `rand_*` callbacks (ids 96-99
 *   and 101-104) that this build does not, because they wrap `ossl_rand_get_entropy` and
 *   friends and are Phase 9's — `core_dispatch.rs`'s own table asserts the absence. So the
 *   *total* entry count differs by exactly eight (53 against 45) and is not observable here.
 *   The probe instead reports the count **excluding that family** and a digest of the ids
 *   outside it, which is strictly stronger than a total: an entry added, dropped,
 *   substituted or reordered anywhere else changes the digest. The family's own absence is
 *   pinned by the crate's unit test and by the ledger, not by this court — the same
 *   arrangement `RT-PROVIDER` uses for `cmod.activate.available`.
 * * **No `EVP` fetch.** The authority's own provider test fetches a decoder, an encoder, a
 *   store loader and a RAND, because that is what `provfetchtest.c` is for. Those are Phase
 *   7's and Phase 9's surfaces, and a probe that needed them would be comparing missing
 *   subsystems rather than the core. What is left is the provider-facing surface, which is
 *   entirely this stratum's.
 * * **No fault observations.** `D-CHILD-DEREGISTER-NULL-1` is the case where a provider
 *   publishes a `CORE_*`-valid table without `PROVIDER_DEREGISTER_CHILD_CB`; the authority
 *   then jumps through NULL when the child is freed. The probe always publishes that entry,
 *   so the case is not reached -- the divergence is recorded in
 *   `docs/SECURITY_DIVERGENCE_POLICY.md` and its teardown half is not measured, for the same
 *   reason `RT-LIBCTX` does not measure it.
 * * **No `global_props_cb` observation.** The core hands the parent that callback. On this
 *   side of the divergence (`D-CHILD-REGISTER-PROPS-1`) the candidate omits the
 *   property-string step, so a probe that observed the callback's being called at
 *   registration time would fail against a recorded, Phase-7-owned divergence. The callback
 *   is stored and its *pointer* is reported as non-NULL -- which both sides agree on --
 *   and whether it is *called* is not observed.
 * * **No `OSSL_PROVIDER_add_conf_parameter`.** The public spelling for adding a
 *   configuration parameter exists and is implemented, but it takes a *loaded* provider, and
 *   the parameters must be in place **before** `init` runs -- which is the only moment
 *   `core_get_params` is called. `OSSL_PROVIDER_load_ex`'s `params` are the path that
 *   satisfies both constraints at once, so that is the one used.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. Nothing is
 * printed from inside `init`: the provider records into file-scope state and `main` reports
 * it, so the transcript's order is `main`'s and not the core's.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------ the deferred dispatch family */

/*
 * The eight `rand_*` core ids this build does not publish, because they wrap
 * `ossl_rand_get_entropy` and friends and are Phase 9's. The list is written out rather than
 * written as a range, because the range has a hole: 100 is `SELF_TEST_CB`, which *is*
 * published. A range test would silently exclude it.
 */
static const int deferred_ids[] = { 96, 97, 98, 99, 101, 102, 103, 104 };

static int is_deferred(int id)
{
    size_t i;

    for (i = 0; i < sizeof deferred_ids / sizeof deferred_ids[0]; i++)
        if (deferred_ids[i] == id)
            return 1;
    return 0;
}

/* FNV-1a over the published id sequence, skipping the deferred family. The offset basis
 * and prime are the 64-bit FNV-1a constants; the point is not cryptographic strength but
 * that one changed id at one position changes the answer, so the observation is a set
 * *and* an order rather than a count. */
static unsigned long long id_digest(unsigned long long h, int id)
{
    unsigned char bytes[4];
    size_t i;

    bytes[0] = (unsigned char)(id & 0xFF);
    bytes[1] = (unsigned char)((id >> 8) & 0xFF);
    bytes[2] = (unsigned char)((id >> 16) & 0xFF);
    bytes[3] = (unsigned char)((id >> 24) & 0xFF);
    for (i = 0; i < sizeof bytes; i++) {
        h ^= bytes[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* ------------------------------------------------------------------ reporting */

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_last_error());
    ERR_clear_error();
}

static void says(const char *key, const char *s)
{
    printf("%s=%s err=%lu\n", key, s == NULL ? "(null)" : s, ERR_peek_last_error());
    ERR_clear_error();
}

/* A 64-bit digest is printed unsigned and zero-padded, because its high bit is as
 * meaningful as its low one and a sign would make half the space look like a fault code. */
static void sayh(const char *key, unsigned long long v)
{
    printf("%s=%016llx err=%lu\n", key, v, ERR_peek_last_error());
    ERR_clear_error();
}

/* ------------------------------------------------------- the provider's state */

/* What the core handed the provider, recorded by `init` and reported by `main`. */
static int t_dispatch_entries;
static int t_first_id;
static unsigned long long t_ids_digest;
static int t_has_get_libctx, t_has_get_params, t_has_thread_start;
static int t_has_register_child, t_has_deregister_child;
static int t_has_malloc, t_has_zalloc, t_has_free;
static int t_has_query_operation, t_has_teardown;

static int t_libctx_matches;
static int t_get_params_ret;
static int t_version_len, t_version_is_prefix;
static char t_prov_name[64];
static int t_conf_param_is_yes_please;
static char t_conf_param[64];
static int t_absent_param_left_alone;

static int t_alloc_roundtrip;
static int t_zalloc_is_zeroed;

static int t_child_nonnull;
static int t_child_slot18_nonnull;
static void *t_child;

static int t_register_ret;
static int t_deregister_cb_returned;
static int t_create_cb_calls;
static int t_remove_cb_calls;
static int t_create_cbdata_is_child;
static int t_create_prov_nonnull;
static const void *t_last_create_prov;
static int t_create_prov_matches_loaded;

static int t_thread_start_ret;
static int t_thread_handler_calls;

static void *t_loader_libctx;

/// The three callbacks a parent hands the core through `PROVIDER_REGISTER_CHILD_CB`, and the
/// three the core hands a child in return. They are the same shape, so one set of counters
/// covers both -- but they are *not* the same functions, and which one runs is the observation.
///
/// `probe_create_cb` records more than a count, because the count alone cannot distinguish a
/// correct call from a call made with the wrong arguments: it records the provider handle and
/// the `cbdata` it was given, and `main` compares the handle against the `OSSL_PROVIDER *` the
/// probe's own `OSSL_PROVIDER_load_ex` returned. That equality is the entry's whole contract --
/// the handle a parent is shown **is** the provider object -- and it is a pointer comparison
/// the probe can make because it holds both ends.
static int probe_create_cb(const OSSL_CORE_HANDLE *prov, void *cbdata)
{
    t_create_cb_calls++;
    t_last_create_prov = (const void *) prov;
    if (prov != NULL)
        t_create_prov_nonnull++;
    if (cbdata == t_child)
        t_create_cbdata_is_child++;
    return 1;
}

static int probe_remove_cb(const OSSL_CORE_HANDLE *prov, void *cbdata)
{
    (void) prov;
    (void) cbdata;
    t_remove_cb_calls++;
    return 1;
}

static int probe_global_props_cb(const char *props, void *cbdata)
{
    (void) props;
    (void) cbdata;
    return 1;
}

static void probe_thread_stop(void *arg)
{
    (void) arg;
    t_thread_handler_calls++;
}

static const OSSL_ALGORITHM *probe_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    (void) operation_id;
    *no_cache = 0;
    return NULL;
}

static void probe_teardown(void *provctx)
{
    /*
     * `provctx` is the child context `init` created, so this is where it is released. That
     * is the authority's own pattern (`dummy_dispatch_table` in `provfetchtest.c` ends with
     * `{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free }`), and it is what
     * closes the child's lifecycle -- which in turn is what makes the core call the parent's
     * `deregister_child_cb`.
     */
    if (provctx != NULL)
        OSSL_LIB_CTX_free(provctx);
}

static const OSSL_DISPATCH probe_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) probe_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) probe_teardown },
    { 0, NULL }
};

static int probe_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out, void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
    OSSL_FUNC_core_thread_start_fn *c_thread_start = NULL;
    OSSL_FUNC_provider_register_child_cb_fn *c_register_child = NULL;
    OSSL_FUNC_provider_deregister_child_cb_fn *c_deregister_child = NULL;
    OSSL_FUNC_CRYPTO_malloc_fn *c_malloc = NULL;
    OSSL_FUNC_CRYPTO_zalloc_fn *c_zalloc = NULL;
    OSSL_FUNC_CRYPTO_free_fn *c_free = NULL;
    const OSSL_DISPATCH *p;
    OSSL_LIB_CTX *child;
    char *buf;
    char *zbuf;
    OSSL_PARAM params[5];
    const char *verptr = NULL;
    const char *nameptr = NULL;
    const char *confptr = NULL;
    const char *absptr = NULL;

    /* ---- the walk: what the core published to this provider ---- */
    t_dispatch_entries = 0;
    t_first_id = in->function_id;
    t_ids_digest = 0xcbf29ce484222325ULL;
    for (p = in; p->function_id != 0; p++) {
        if (!is_deferred(p->function_id)) {
            t_dispatch_entries++;
            t_ids_digest = id_digest(t_ids_digest, p->function_id);
        }
        switch (p->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(p);
            t_has_get_libctx = 1;
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(p);
            t_has_get_params = 1;
            break;
        case OSSL_FUNC_CORE_THREAD_START:
            c_thread_start = OSSL_FUNC_core_thread_start(p);
            t_has_thread_start = 1;
            break;
        case OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB:
            c_register_child = OSSL_FUNC_provider_register_child_cb(p);
            t_has_register_child = 1;
            break;
        case OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB:
            c_deregister_child = OSSL_FUNC_provider_deregister_child_cb(p);
            t_has_deregister_child = 1;
            break;
        case OSSL_FUNC_CRYPTO_MALLOC:
            c_malloc = OSSL_FUNC_CRYPTO_malloc(p);
            t_has_malloc = 1;
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            c_zalloc = OSSL_FUNC_CRYPTO_zalloc(p);
            t_has_zalloc = 1;
            break;
        case OSSL_FUNC_CRYPTO_FREE:
            c_free = OSSL_FUNC_CRYPTO_free(p);
            t_has_free = 1;
            break;
        case OSSL_FUNC_PROVIDER_QUERY_OPERATION:
            t_has_query_operation = 1;
            break;
        case OSSL_FUNC_PROVIDER_TEARDOWN:
            t_has_teardown = 1;
            break;
        default:
            break;
        }
    }

    /* ---- `CORE_GET_LIBCTX` answers the context this provider was loaded into ---- */
    if (c_get_libctx != NULL)
        t_libctx_matches =
            (const void *) c_get_libctx(handle) == (const void *) t_loader_libctx;

    /* ---- `CORE_GET_PARAMS`: the two required keys, a configuration key, and one that is
     * not set at all ---- */
    if (c_get_params != NULL) {
        params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_CORE_VERSION,
                                                  (char **) &verptr, 0);
        params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_CORE_PROV_NAME,
                                                  (char **) &nameptr, 0);
        params[2] = OSSL_PARAM_construct_utf8_ptr("rt-3p-conf",
                                                  (char **) &confptr, 0);
        params[3] = OSSL_PARAM_construct_utf8_ptr("rt-3p-absent",
                                                  (char **) &absptr, 0);
        params[4] = OSSL_PARAM_construct_end();
        t_get_params_ret = c_get_params(handle, params);
        if (t_get_params_ret == 1) {
            if (verptr != NULL) {
                t_version_len = (int) strlen(verptr);
                t_version_is_prefix = strncmp(verptr, "3.", 2) == 0;
            }
            if (nameptr != NULL)
                snprintf(t_prov_name, sizeof t_prov_name, "%s", nameptr);
            if (confptr != NULL) {
                snprintf(t_conf_param, sizeof t_conf_param, "%s", confptr);
                t_conf_param_is_yes_please = strcmp(confptr, "yes-please") == 0;
            }
            /* The absent key is the negative half: `OSSL_PARAM_modified` false *and* the
             * pointer still NULL, which is what "left alone" means for a `UTF8_PTR` slot.
             * Both halves are needed -- a core that wrote NULL through the pointer would
             * satisfy the second while having touched the descriptor. */
            t_absent_param_left_alone =
                !OSSL_PARAM_modified(&params[3]) && absptr == NULL;
        }
    }

    /* ---- the `CRYPTO_*` trio ---- */
    if (c_malloc != NULL && c_zalloc != NULL && c_free != NULL) {
        /* `CORE`-side allocation carries the *provider's* file and line, so a provider's
         * allocation is attributable in the core's own accounting. The two arguments are
         * part of the entry's signature rather than a convention. */
        buf = c_malloc(16, OPENSSL_FILE, OPENSSL_LINE);
        zbuf = c_zalloc(16, OPENSSL_FILE, OPENSSL_LINE);
        if (buf != NULL && zbuf != NULL) {
            memset(buf, 0x5A, 16);
            t_alloc_roundtrip = buf[0] == 0x5A && buf[15] == 0x5A;
            t_zalloc_is_zeroed = zbuf[0] == 0 && zbuf[15] == 0;
            c_free(buf, OPENSSL_FILE, OPENSSL_LINE);
            c_free(zbuf, OPENSSL_FILE, OPENSSL_LINE);
        }
    }

    /* ---- a child context, created from inside a provider's init ---- */
    child = OSSL_LIB_CTX_new_child(handle, in);
    t_child = child;
    t_child_nonnull = child != NULL;
    if (child != NULL) {
        /* Slot 18 is the child-provider globals; it exists for every context, so this is
         * about the slot and not about the child. */
        t_child_slot18_nonnull = OSSL_LIB_CTX_get_data(child, 18) != NULL;

        /* ---- the child-callback pair ---- */
        if (c_register_child != NULL) {
            t_register_ret = c_register_child(handle, probe_create_cb, probe_remove_cb,
                                              probe_global_props_cb, child);
        }
        if (c_deregister_child != NULL) {
            c_deregister_child(handle);
            /* The entry is `void`, so there is no answer to compare and this is a *liveness*
             * witness rather than a status: reaching the next line means the deregistration
             * neither crashed nor recursed into the probe. The candidate's teardown-half
             * divergence (`D-CHILD-DEREGISTER-NULL-1`) is not reachable here, because this
             * probe publishes the entry. */
            t_deregister_cb_returned = 1;
        }
    }

    /* ---- `CORE_THREAD_START`: register a handler and let the thread stop run it ---- */
    if (c_thread_start != NULL)
        t_thread_start_ret = c_thread_start(handle, probe_thread_stop, NULL);
    OPENSSL_thread_stop();

    *provctx = child;
    *out = probe_functions;
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *p;
    OSSL_PARAM loadparams[2];
    int ret;

    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }

    /* A configuration parameter for this provider, so `core_get_params` has something to
     * merge over the two keys it answers itself. It must be in place *before* `init` runs,
     * because `init` is the only place `core_get_params` is called -- and `OSSL_PROVIDER_load_ex`
     * is the public entry point that takes parameters at exactly that moment. Only
     * `OSSL_PARAM_UTF8_STRING` entries are read; any other type is skipped silently, which is
     * why the value's `data_size` is left 0 (the string is NUL-terminated in place). */
    t_loader_libctx = ctx;
    ret = OSSL_PROVIDER_add_builtin(ctx, "rt-3p", probe_provider_init);
    sayn("add_builtin", ret);

    loadparams[0] = OSSL_PARAM_construct_utf8_string("rt-3p-conf",
                                                    (char *)"yes-please", 0);
    loadparams[1] = OSSL_PARAM_construct_end();

    p = OSSL_PROVIDER_load_ex(ctx, "rt-3p", loadparams);
    says("load", p == NULL ? "NULL" : "nonnull");

    /* The comparison the create callback's handle exists for, made here because `init` runs
     * before `load_ex` returns and therefore cannot see `p`. `probe_create_cb` ran during
     * `ossl_provider_add_to_store`, which is after `init` and still inside the load, so by now
     * both pointers are known. */
    t_create_prov_matches_loaded =
        t_last_create_prov != NULL && t_last_create_prov == (const void *) p;

    /* The provider's own report, in `main`'s order rather than the core's. */
    sayn("in.entries_non_deferred", t_dispatch_entries);
    sayn("in.first_id", t_first_id);
    sayh("in.ids_digest", t_ids_digest);
    sayn("in.get_libctx", t_has_get_libctx);
    sayn("in.get_params", t_has_get_params);
    sayn("in.thread_start", t_has_thread_start);
    sayn("in.register_child", t_has_register_child);
    sayn("in.deregister_child", t_has_deregister_child);
    sayn("in.malloc", t_has_malloc);
    sayn("in.zalloc", t_has_zalloc);
    sayn("in.free", t_has_free);
    /* The two `PROVIDER_*` ids are *this* provider's own table, handed to the core, and the
     * walk sees them because the probe walked its *input* table -- which is the core's. So
     * these two must be 0: a core that published its own provider entries to a provider
     * would be publishing the wrong table, and that is what makes the pair an observation
     * rather than a tautology. */
    sayn("in.query_operation_is_the_cores", t_has_query_operation);
    sayn("in.teardown_is_the_cores", t_has_teardown);

    sayn("libctx.matches_loader", t_libctx_matches);
    sayn("params.get_params_ret", t_get_params_ret);
    sayn("params.version_len_is_nonzero", t_version_len > 0);
    sayn("params.version_starts_with_3", t_version_is_prefix);
    says("params.prov_name", t_prov_name);
    sayn("params.conf_param_is_yes_please", t_conf_param_is_yes_please);
    says("params.conf_param", t_conf_param);
    sayn("params.absent_key_left_alone", t_absent_param_left_alone);

    sayn("alloc.roundtrip", t_alloc_roundtrip);
    sayn("alloc.zalloc_is_zeroed", t_zalloc_is_zeroed);

    sayn("child.nonnull", t_child_nonnull);
    sayn("child.slot18", t_child_slot18_nonnull);
    sayn("child.register_child_ret", t_register_ret);
    sayn("child.deregister_cb_returned", t_deregister_cb_returned);
    sayn("child.create_cb_calls", t_create_cb_calls);
    sayn("child.remove_cb_calls", t_remove_cb_calls);
    sayn("child.create_cb_prov_nonnull", t_create_prov_nonnull);
    sayn("child.create_cb_prov_is_the_loaded_provider", t_create_prov_matches_loaded);
    sayn("child.create_cb_cbdata_is_the_child", t_create_cbdata_is_child);

    sayn("thread.start_ret", t_thread_start_ret);
    sayn("thread.handler_calls", t_thread_handler_calls);

    /* Now the unload: `PROVIDER_TEARDOWN` frees the child, which is what makes the core call
     * the parent's `deregister_child_cb` -- the callback the probe's `register_child_cb` was
     * handed. That callback is the core's, so what is observable from here is that the whole
     * path returns and that the library is still consistent afterwards. */
    sayn("unload", OSSL_PROVIDER_unload(p));
    sayn("available.after_unload", OSSL_PROVIDER_available(ctx, "rt-3p"));
    sayn("err.clear", ERR_peek_error() == 0);

    OSSL_LIB_CTX_free(ctx);
    says("done", "rt-provider-3p");
    return 0;
}
