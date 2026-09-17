/*
 * RT-EVP-KEYMGMT -- the `EVP_KEYMGMT` method object, and the structural check that admits it.
 *
 * The fifth provider-only method class and the one every provider-side `EVP_PKEY` is built on. Its
 * court has one thing to do that no sibling court had to do: the structural check is **eight
 * counters and two non-counter clauses**, and six of the eight counters are *pairwise*, so a court
 * that only publishes well-formed methods measures nothing. Every arm below is therefore published
 * as its own algorithm with its own name, one for each way the check can be satisfied and one for
 * each way it can be refused.
 *
 * What is observable, and what makes each arm worth a transcript
 * -------------------------------------------------------------
 *   1. **`free` is the *key data* destructor, not the method's.** `EVP_KEYMGMT_free` releases the
 *      method object and never calls the provider's `free` -- that callback is reached from
 *      `evp_keymgmt_freedata`, which no export enters yet. So the final counter line is an
 *      observation and not a formality: `final.provider_free_calls=0` is what distinguishes the two
 *      plausible readings of the field.
 *   2. **the pair counters count *arms*, not entries, and are guarded.** Every arm of the walk is
 *      `if (field == NULL) { count++; field = ...; }`, so listing the same dispatch id twice counts
 *      once -- which turns a duplicate into a *refusal* for the four counted descriptors and into a
 *      silently-ignored second entry for the five uncounted ones. `KMGM-GetTableTwice` and
 *      `KMGM-DupImport` are the two arms that state this, and both are refused.
 *   3. **the two descriptor counters count *spellings*.** `import_types` and `import_types_ex` are
 *      alternatives under one counter that increments only for the first of them, so
 *      `import` + both spellings is accepted with the same count as `import` + one, and an
 *      importer with *no* descriptor is refused. `KMGM-ImportBothSpellings`,
 *      `KMGM-ImportNoDescriptor` and `KMGM-ImportNoImporter` are the three arms.
 *   4. **"at least one constructor" is an `||` and not a count.** `KMGM-LoadOnly` publishes `load`
 *      and neither `new` nor `gen` and is accepted; `KMGM-NoConstructor` publishes neither and is
 *      refused. A transcription that required `new` specifically would fail the first and pass the
 *      second.
 *   5. **the `gen` clause is separate from the counter clause.** `KMGM-NoGenInit` and
 *      `KMGM-NoGenCleanup` publish a `gen` and one of its two halves, and are refused by the last
 *      clause rather than by any counter -- so a court that only tested counts would miss them.
 *   6. **no dispatch id is 9.** `LOAD` is 8 and `FREE` is 10. The probe publishes every arm with the
 *      *header's* `OSSL_FUNC_KEYMGMT_*` constants and the candidate links the same installed header,
 *      so a transcription that assumed the ids were dense would read the probe's `free` as its own
 *      `settable_params`: the accepted arms would then be refused for having no destructor and the
 *      transcript would say so on the first line that matters.
 *   7. **the four descriptor accessors are call-throughs, and calling one is an observation.**
 *      `EVP_KEYMGMT_gettable_params` and its three siblings ask the *provider*, so each increments a
 *      counter, and each answers NULL for a method that publishes none. `KMGM-LoadOnly` publishes
 *      none, which is why the same four calls are made twice in the transcript with two different
 *      answers.
 *   8. **the store answers the same object for a second fetch, and an alias resolves to it.** Both
 *      are pointer *relations* this probe holds, so neither prints an address.
 *
 * Deliberately not observed
 * -------------------------
 *   * **`legacy_alg`.** `keymgmt_from_algorithm`'s last statement fills it from
 *     `evp_pkey_name2type`, and nothing in `evp.h` reads it back: the field is consumed by
 *     `evp_keymgmt_util_*` and by `EVP_PKEY_CTX_new_from_pkey`, which is 7.4c's. So a probe cannot
 *     see it yet and does not pretend to; when 7.4c lands, a context opened from a legacy name is
 *     where it becomes observable, and `RT-EVP-PKEY` is where that belongs.
 *   * **the reference count `EVP_KEYMGMT_up_ref` moves.** It has no observable: the method object's
 *     destructor is internal, and the provider callback that would show it is the *key data's*.
 *     `up_ref`'s return code is printed, which is all there is.
 *   * **`query_operation_name`.** Its only reader is `evp_keymgmt_util_query_operation_name`, which
 *     no export enters. The arm publishes it so that the accepted methods have one, and nothing
 *     more is claimed.
 *   * **`EVP_KEYMGMT_do_all_provided(ctx, NULL, arg)`**, which faults the authority
 *     (D-MD-DOALL-NULL-1). The boundary is printed.
 *   * **the four parameter accessors on a NULL method.** `EVP_KEYMGMT_gettable_params(NULL)` and
 *     its three siblings read a field of the method before testing the callback, so they fault the
 *     authority -- measured once, exit 139, and the boundary is printed rather than compared. The
 *     crate answers NULL; that is `D-KEYMGMT-PARAMS-NULL-1`.
 *   * **`EVP_KEYMGMT_up_ref(NULL)` / `EVP_KEYMGMT_get0_name(NULL)` / `EVP_KEYMGMT_get0_provider(NULL)`
 *     / `EVP_KEYMGMT_names_do_all(NULL, ...)`**, which dereference in the authority and are
 *     therefore not called. `EVP_KEYMGMT_is_a(NULL, ...)` *is* called: it is the one entry point in
 *     this class that tests its method pointer, and it answers 0.
 *
 * Addresses are never printed. Every observation is a relation between two pointers this probe
 * holds, a presence answer, a counter vector, a bounded byte comparison or a return code.
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

/* ---- the counters, and the call-throughs that move them ----
 *
 * Only four of them can be moved from outside the library, and that is the point rather than a
 * limitation to work around: `gettable_params`, `settable_params`, `gen_settable_params` and
 * `gen_gettable_params` have exported callers, and every other callback in this class is reached
 * only through `evp_keymgmt_*`, which no export enters yet. Each of the four returns a distinct
 * static table, so an accessor that asked the wrong callback would be visible as the wrong table
 * rather than merely as a wrong count.
 */

static int k_gettable, k_settable, k_gen_settable, k_gen_gettable;
/* The provider's own destructor. `EVP_KEYMGMT_free` must never reach it: the callback frees *key
 * data*, and `evp_keymgmt_freedata` is its only caller. Nothing here may move it. */
static int k_free;

static const OSSL_PARAM kmgm_gettable[] = {
    OSSL_PARAM_utf8_string("court-gettable", NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM kmgm_settable[] = {
    OSSL_PARAM_utf8_string("court-settable", NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM kmgm_gen_settable[] = {
    OSSL_PARAM_utf8_string("court-gen-settable", NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM kmgm_gen_gettable[] = {
    OSSL_PARAM_utf8_string("court-gen-gettable", NULL, 0),
    OSSL_PARAM_END
};

static void reset_counts(void)
{
    k_gettable = k_settable = k_gen_settable = k_gen_gettable = 0;
}

static void say_vec(const char *key)
{
    printf("%s=%d,%d,%d,%d err=%lu\n", key, k_gettable, k_settable, k_gen_settable,
           k_gen_gettable, ERR_peek_error());
    ERR_clear_error();
}

static int kmgm_has(const void *keydata, int selection)
{
    (void) keydata;
    (void) selection;
    return 1;
}

static void kmgm_free(void *keydata)
{
    k_free++;
    free(keydata);
}

static void *kmgm_new(void *provctx)
{
    (void) provctx;
    return malloc(1);
}

static void *kmgm_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void) provctx;
    (void) selection;
    (void) params;
    return malloc(1);
}

static void kmgm_gen_cleanup(void *genctx)
{
    free(genctx);
}

static void *kmgm_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    (void) genctx;
    (void) cb;
    (void) cbarg;
    return malloc(1);
}

static void *kmgm_load(const void *reference, size_t reference_sz)
{
    (void) reference;
    (void) reference_sz;
    return malloc(1);
}

static int kmgm_get_params(void *keydata, OSSL_PARAM params[])
{
    (void) keydata;
    (void) params;
    return 1;
}

static int kmgm_set_params(void *keydata, const OSSL_PARAM params[])
{
    (void) keydata;
    (void) params;
    return 1;
}

static int kmgm_gen_get_params(void *genctx, OSSL_PARAM params[])
{
    (void) genctx;
    (void) params;
    return 1;
}

static int kmgm_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    (void) genctx;
    (void) params;
    return 1;
}

static int kmgm_gen_set_template(void *genctx, void *templ)
{
    (void) genctx;
    (void) templ;
    return 1;
}

static const char *kmgm_query_operation_name(int operation_id)
{
    (void) operation_id;
    return NULL;
}

static void *kmgm_dup(const void *keydata_from, int selection)
{
    (void) keydata_from;
    (void) selection;
    return malloc(1);
}

static int kmgm_validate(const void *keydata, int selection, int checktype)
{
    (void) keydata;
    (void) selection;
    (void) checktype;
    return 1;
}

static int kmgm_match(const void *keydata1, const void *keydata2, int selection)
{
    (void) keydata1;
    (void) keydata2;
    (void) selection;
    return 1;
}

static void *kmgm_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    (void) keydata;
    (void) selection;
    (void) params;
    return malloc(1);
}

static int kmgm_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    (void) keydata;
    (void) selection;
    (void) param_cb;
    (void) cbarg;
    return 1;
}

static const OSSL_PARAM *kmgm_import_types(int selection)
{
    (void) selection;
    return NULL;
}

static const OSSL_PARAM *kmgm_import_types_ex(void *provctx, int selection)
{
    (void) provctx;
    (void) selection;
    return NULL;
}

static const OSSL_PARAM *kmgm_export_types(int selection)
{
    (void) selection;
    return NULL;
}

static const OSSL_PARAM *kmgm_export_types_ex(void *provctx, int selection)
{
    (void) provctx;
    (void) selection;
    return NULL;
}

/* The four counted descriptors, each incrementing its own counter. */
static const OSSL_PARAM *kmgm_gettable_params(void *provctx)
{
    k_gettable++;
    (void) provctx;
    return kmgm_gettable;
}

static const OSSL_PARAM *kmgm_settable_params(void *provctx)
{
    k_settable++;
    (void) provctx;
    return kmgm_settable;
}

static const OSSL_PARAM *kmgm_gen_settable_params(void *genctx, void *provctx)
{
    k_gen_settable++;
    (void) genctx;
    (void) provctx;
    return kmgm_gen_settable;
}

static const OSSL_PARAM *kmgm_gen_gettable_params(void *genctx, void *provctx)
{
    k_gen_gettable++;
    (void) genctx;
    (void) provctx;
    return kmgm_gen_gettable;
}

/* A second `gettable_params`, so the duplicate arm can show that the *first* entry is the one the
 * walk kept -- by being the one the accessor returns. */
static const OSSL_PARAM *kmgm_gettable_params_second(void *provctx)
{
    (void) provctx;
    return kmgm_settable;
}

/* ---- the arms ----
 *
 * Each table names its own algorithm, so a refusal cannot shadow an acceptance. The mandatory three
 * (`free`, a constructor, `has`) are present wherever the arm is not *about* one of them.
 */

/* Every optional callback, including both spellings of both descriptor pairs' alternatives. */
static const OSSL_DISPATCH kmgm_full_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) kmgm_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) kmgm_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void)) kmgm_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void)) kmgm_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) kmgm_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void)) kmgm_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) kmgm_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) kmgm_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void)) kmgm_gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (void (*)(void)) kmgm_gen_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) kmgm_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) kmgm_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) kmgm_load },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void)) kmgm_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) kmgm_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) kmgm_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) kmgm_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) kmgm_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void)) kmgm_dup },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void)) kmgm_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void)) kmgm_match },
    { 0, NULL }
};

/* The constructor is `load` alone: accepted, because the clause is an `||`. */
static const OSSL_DISPATCH kmgm_loadonly_fns[] = {
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) kmgm_load },
    { 0, NULL }
};

/* The constructor is `gen` alone, with both of its halves: accepted. No parameter descriptor is
 * published, which is what makes the four accessor calls answer NULL on this arm. */
static const OSSL_DISPATCH kmgm_genonly_fns[] = {
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) kmgm_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) kmgm_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) kmgm_gen_cleanup },
    { 0, NULL }
};

/* Bad: no destructor. */
static const OSSL_DISPATCH kmgm_nofree_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { 0, NULL }
};

/* Bad: no content test. */
static const OSSL_DISPATCH kmgm_nohas_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { 0, NULL }
};

/* Bad: `free` and `has` and nothing that can build key data. */
static const OSSL_DISPATCH kmgm_noconstructor_fns[] = {
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { 0, NULL }
};

/* Bad: a `gen` with no `gen_init`. */
static const OSSL_DISPATCH kmgm_nogeninit_fns[] = {
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) kmgm_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) kmgm_gen_cleanup },
    { 0, NULL }
};

/* Bad: a `gen` with no `gen_cleanup`. */
static const OSSL_DISPATCH kmgm_nogencleanup_fns[] = {
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) kmgm_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) kmgm_gen },
    { 0, NULL }
};

/* Bad: half of the get-parameter pair. */
static const OSSL_DISPATCH kmgm_gethalf_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) kmgm_get_params },
    { 0, NULL }
};

/* Bad: half of the set-parameter pair, and the *descriptor* half rather than the function half --
 * the two are interchangeable to the counter. */
static const OSSL_DISPATCH kmgm_sethalf_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void)) kmgm_settable_params },
    { 0, NULL }
};

/* Bad: half of the generation get-parameter pair. */
static const OSSL_DISPATCH kmgm_gengethalf_fns[] = {
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) kmgm_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) kmgm_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) kmgm_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void)) kmgm_gen_get_params },
    { 0, NULL }
};

/* Bad: half of the generation set-parameter pair. */
static const OSSL_DISPATCH kmgm_gensethalf_fns[] = {
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) kmgm_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) kmgm_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) kmgm_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) kmgm_gen_settable_params },
    { 0, NULL }
};

/* Bad: an importer with no descriptor of either spelling. */
static const OSSL_DISPATCH kmgm_importnodesc_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) kmgm_import },
    { 0, NULL }
};

/* Bad: a descriptor with no importer, which is the same count from the other side. */
static const OSSL_DISPATCH kmgm_importnodesc2_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) kmgm_import_types },
    { 0, NULL }
};

/* Bad: the same for export. */
static const OSSL_DISPATCH kmgm_exportnodesc_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) kmgm_export },
    { 0, NULL }
};

/* Accepted: an importer and *both* spellings of its descriptor. The counter increments once, for
 * the first spelling, so this is legal and the second spelling is simply also stored. */
static const OSSL_DISPATCH kmgm_importboth_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) kmgm_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) kmgm_import_types },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX, (void (*)(void)) kmgm_import_types_ex },
    { 0, NULL }
};

/* Accepted: the same on the export side. */
static const OSSL_DISPATCH kmgm_exportboth_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) kmgm_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) kmgm_export_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX, (void (*)(void)) kmgm_export_types_ex },
    { 0, NULL }
};

/* Accepted: the get-parameter pair, both halves. The counterpart of `kmgm_gethalf_fns`, and the
 * arm whose accessor calls are the transcript's counter vector. */
static const OSSL_DISPATCH kmgm_getpair_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) kmgm_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) kmgm_gettable_params },
    { 0, NULL }
};

/* Bad, and the arm that states the guard: the *same* dispatch id twice counts once, so a method
 * whose only descriptor arm is duplicated has a count of one and is refused. Both plausible
 * mis-readings -- "count the entries" and "count distinct fields" -- give two and accept it. */
static const OSSL_DISPATCH kmgm_gettabletwice_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) kmgm_gettable_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) kmgm_gettable_params_second },
    { 0, NULL }
};

/* Bad, and the same guard on the importer: `import` listed twice is *one* importer, so with no
 * descriptor the count is one and the method is refused. A court that counted table entries rather
 * than counted arms would accept it -- which is exactly what this arm is for. */
static const OSSL_DISPATCH kmgm_dupimport_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kmgm_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kmgm_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kmgm_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) kmgm_import },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) kmgm_import },
    { 0, NULL }
};

/* ---- the two bodies of published algorithms ---- */

#define COURT_KMGMS(PROVIDER, TAG)                                                  \
    { "KMGM-Full:KMGM-full:courtkmgmfull", PROVIDER, kmgm_full_fns,                \
      "every callback, and every alternative spelling (" TAG ")" },                 \
    { "KMGM-LoadOnly:KMGM-loadonly:courtkmgmloadonly", PROVIDER, kmgm_loadonly_fns, \
      "the constructor is load alone" },                                            \
    { "KMGM-GenOnly:KMGM-genonly:courtkmgmgenonly", PROVIDER, kmgm_genonly_fns,     \
      "the constructor is gen alone, with no parameter descriptors" },              \
    { "KMGM-GetPair:KMGM-getpair:courtkmgmgetpair", PROVIDER, kmgm_getpair_fns,     \
      "the get-parameter pair, complete" },                                         \
    { "KMGM-ImportBoth:KMGM-importboth:courtkmgmimportboth", PROVIDER,              \
      kmgm_importboth_fns, "an importer and both descriptor spellings" },           \
    { "KMGM-ExportBoth:KMGM-exportboth:courtkmgmexportboth", PROVIDER,              \
      kmgm_exportboth_fns, "an exporter and both descriptor spellings" },           \
    { "KMGM-NoFree:KMGM-nofree:courtkmgmnofree", PROVIDER, kmgm_nofree_fns,         \
      "refused: no destructor" },                                                   \
    { "KMGM-NoHas:KMGM-nohas:courtkmgmnohas", PROVIDER, kmgm_nohas_fns,             \
      "refused: no content test" },                                                 \
    { "KMGM-NoConstructor:KMGM-noconstructor:courtkmgmnoconstructor", PROVIDER,      \
      kmgm_noconstructor_fns, "refused: nothing can build key data" },              \
    { "KMGM-NoGenInit:KMGM-nogeninit:courtkmgmnogeninit", PROVIDER,                 \
      kmgm_nogeninit_fns, "refused: a gen with no gen_init" },                      \
    { "KMGM-NoGenCleanup:KMGM-nogencleanup:courtkmgmnogencleanup", PROVIDER,        \
      kmgm_nogencleanup_fns, "refused: a gen with no gen_cleanup" },                \
    { "KMGM-GetHalf:KMGM-gethalf:courtkmgmgethalf", PROVIDER, kmgm_gethalf_fns,     \
      "refused: half the get-parameter pair" },                                     \
    { "KMGM-SetHalf:KMGM-sethalf:courtkmgmsethalf", PROVIDER, kmgm_sethalf_fns,     \
      "refused: half the set-parameter pair, on the descriptor half" },             \
    { "KMGM-GenGetHalf:KMGM-gengethalf:courtkmgmgengethalf", PROVIDER,              \
      kmgm_gengethalf_fns, "refused: half the generation get-parameter pair" },     \
    { "KMGM-GenSetHalf:KMGM-gensethalf:courtkmgmgensethalf", PROVIDER,              \
      kmgm_gensethalf_fns, "refused: half the generation set-parameter pair" },     \
    { "KMGM-ImportNoDesc:KMGM-importnodesc:courtkmgmimportnodesc", PROVIDER,        \
      kmgm_importnodesc_fns, "refused: an importer with no descriptor" },           \
    { "KMGM-ImportNoImporter:KMGM-importnodesc2:courtkmgmimportnodesc2", PROVIDER,  \
      kmgm_importnodesc2_fns, "refused: a descriptor with no importer" },           \
    { "KMGM-ExportNoDesc:KMGM-exportnodesc:courtkmgmexportnodesc", PROVIDER,        \
      kmgm_exportnodesc_fns, "refused: an exporter with no descriptor" },           \
    { "KMGM-GetTableTwice:KMGM-gettabletwice:courtkmgmgettabletwice", PROVIDER,     \
      kmgm_gettabletwice_fns, "refused: the same descriptor arm twice" },           \
    { "KMGM-DupImport:KMGM-dupimport:courtkmgmdupimport", PROVIDER, kmgm_dupimport_fns, \
      "refused: the same importer arm twice" },                                     \
    { NULL, NULL, NULL, NULL }

#define COURT_PROPS(NAME) "provider=" NAME

static const OSSL_ALGORITHM court_a_keymgmts[] = {
    COURT_KMGMS(COURT_PROPS("court-kmgm"), "a")
};
static const OSSL_ALGORITHM court_b_keymgmts[] = {
    COURT_KMGMS(COURT_PROPS("court-kmgm-b"), "b")
};

static const OSSL_ALGORITHM *court_a_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return court_a_keymgmts;
    return NULL;
}

static const OSSL_DISPATCH court_a_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_a_query },
    { 0, NULL }
};

static char marker_a;

static int court_a_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                        const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_a_dispatch;
    *provctx = (void *) (size_t) 1;
    (void) marker_a;
    return 1;
}

static const OSSL_ALGORITHM *court_b_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return court_b_keymgmts;
    return NULL;
}

static const OSSL_DISPATCH court_b_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_b_query },
    { 0, NULL }
};

static int court_b_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                        const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_b_dispatch;
    /* The provider context is the flavour, so a method says which provider made it. */
    *provctx = (void *) (size_t) 2;
    return 1;
}

/* ---- the visitors ---- */

struct kmgm_seen {
    int count;
    int saw_full;
    int saw_loadonly;
    int saw_a_refused_one;
};

static void kmgm_visitor(EVP_KEYMGMT *mgmt, void *arg)
{
    struct kmgm_seen *s = arg;
    const char *name = EVP_KEYMGMT_get0_name(mgmt);

    s->count++;
    if (name != NULL && strcmp(name, "KMGM-Full") == 0)
        s->saw_full = 1;
    if (name != NULL && strcmp(name, "KMGM-LoadOnly") == 0)
        s->saw_loadonly = 1;
    if (name != NULL && strcmp(name, "KMGM-NoFree") == 0)
        s->saw_a_refused_one = 1;
}

struct kmgm_names {
    int count;
    int saw_identity;
    int saw_alias;
};

static void kmgm_name_visitor(const char *name, void *arg)
{
    struct kmgm_names *s = arg;

    s->count++;
    if (strcmp(name, "KMGM-Full") == 0)
        s->saw_identity = 1;
    if (strcmp(name, "courtkmgmfull") == 0)
        s->saw_alias = 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *a, *b;
    EVP_KEYMGMT *full, *loadonly, *genonly, *getpair, *importboth, *exportboth;
    EVP_KEYMGMT *nofree, *nohas, *noconstructor, *nogeninit, *nogencleanup;
    EVP_KEYMGMT *gethalf, *sethalf, *gengethalf, *gensethalf;
    EVP_KEYMGMT *importnodesc, *importnodesc2, *exportnodesc;
    EVP_KEYMGMT *gettabletwice, *dupimport;
    EVP_KEYMGMT *again, *rejected, *unknown, *from_b;

    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }
    sayn("add_builtin.a", OSSL_PROVIDER_add_builtin(ctx, "court-kmgm", court_a_init));
    sayn("add_builtin.b", OSSL_PROVIDER_add_builtin(ctx, "court-kmgm-b", court_b_init));
    a = OSSL_PROVIDER_load(ctx, "court-kmgm");
    b = OSSL_PROVIDER_load(ctx, "court-kmgm-b");
    sayn("load.a", a != NULL ? 1 : 0);
    sayn("load.b", b != NULL ? 1 : 0);
    if (a == NULL || b == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    reset_counts();

    /*
     * ---- the structural check, one arm at a time ----
     *
     * Twenty algorithms, six of which must be constructible and fourteen of which must be refused.
     * Every refusal leaves `EVP_R_INVALID_PROVIDER_FUNCTIONS` behind, which is the same reason code
     * for all fourteen -- the check has one exit -- so the *presence* of the refusal is the
     * observation and the code is a second one.
     */
    full = EVP_KEYMGMT_fetch(ctx, "KMGM-Full", NULL);
    loadonly = EVP_KEYMGMT_fetch(ctx, "KMGM-LoadOnly", NULL);
    genonly = EVP_KEYMGMT_fetch(ctx, "KMGM-GenOnly", NULL);
    getpair = EVP_KEYMGMT_fetch(ctx, "KMGM-GetPair", NULL);
    importboth = EVP_KEYMGMT_fetch(ctx, "KMGM-ImportBoth", NULL);
    exportboth = EVP_KEYMGMT_fetch(ctx, "KMGM-ExportBoth", NULL);
    sayp("fetch.full", full);
    sayp("fetch.load_only", loadonly);
    sayp("fetch.gen_only", genonly);
    sayp("fetch.get_pair", getpair);
    sayp("fetch.import_both_spellings", importboth);
    sayp("fetch.export_both_spellings", exportboth);

    nofree = EVP_KEYMGMT_fetch(ctx, "KMGM-NoFree", NULL);
    sayp("fetch.no_free", nofree);
    nohas = EVP_KEYMGMT_fetch(ctx, "KMGM-NoHas", NULL);
    sayp("fetch.no_has", nohas);
    noconstructor = EVP_KEYMGMT_fetch(ctx, "KMGM-NoConstructor", NULL);
    sayp("fetch.no_constructor", noconstructor);
    nogeninit = EVP_KEYMGMT_fetch(ctx, "KMGM-NoGenInit", NULL);
    sayp("fetch.no_gen_init", nogeninit);
    nogencleanup = EVP_KEYMGMT_fetch(ctx, "KMGM-NoGenCleanup", NULL);
    sayp("fetch.no_gen_cleanup", nogencleanup);
    gethalf = EVP_KEYMGMT_fetch(ctx, "KMGM-GetHalf", NULL);
    sayp("fetch.get_half", gethalf);
    sethalf = EVP_KEYMGMT_fetch(ctx, "KMGM-SetHalf", NULL);
    sayp("fetch.set_half", sethalf);
    gengethalf = EVP_KEYMGMT_fetch(ctx, "KMGM-GenGetHalf", NULL);
    sayp("fetch.gen_get_half", gengethalf);
    gensethalf = EVP_KEYMGMT_fetch(ctx, "KMGM-GenSetHalf", NULL);
    sayp("fetch.gen_set_half", gensethalf);
    importnodesc = EVP_KEYMGMT_fetch(ctx, "KMGM-ImportNoDesc", NULL);
    sayp("fetch.import_no_descriptor", importnodesc);
    importnodesc2 = EVP_KEYMGMT_fetch(ctx, "KMGM-ImportNoImporter", NULL);
    sayp("fetch.descriptor_no_importer", importnodesc2);
    exportnodesc = EVP_KEYMGMT_fetch(ctx, "KMGM-ExportNoDesc", NULL);
    sayp("fetch.export_no_descriptor", exportnodesc);
    gettabletwice = EVP_KEYMGMT_fetch(ctx, "KMGM-GetTableTwice", NULL);
    sayp("fetch.descriptor_arm_twice", gettabletwice);
    dupimport = EVP_KEYMGMT_fetch(ctx, "KMGM-DupImport", NULL);
    sayp("fetch.importer_arm_twice", dupimport);

    unknown = EVP_KEYMGMT_fetch(ctx, "no-such-key-type", NULL);
    sayp("fetch.unknown_name", unknown);
    rejected = EVP_KEYMGMT_fetch(ctx, "KMGM-Full", "provider=other");
    sayp("fetch.rejected_property", rejected);

    /*
     * ---- the store: the same object for a second fetch, and an alias resolving to it ----
     */
    again = EVP_KEYMGMT_fetch(ctx, "KMGM-Full", NULL);
    printf("fetch.same_object_for_a_second_fetch=%d\n", again == full ? 1 : 0);
    EVP_KEYMGMT_free(again);
    again = EVP_KEYMGMT_fetch(ctx, "courtkmgmfull", NULL);
    printf("fetch.alias_resolves_to_the_same_object=%d\n", again == full ? 1 : 0);
    EVP_KEYMGMT_free(again);
    from_b = EVP_KEYMGMT_fetch(ctx, "KMGM-Full", "provider=court-kmgm-b");
    printf("fetch.second_provider_distinct_object=%d\n",
           from_b != NULL && from_b != full ? 1 : 0);
    printf("fetch.second_provider_has_its_own_description=%d\n",
           from_b != NULL && EVP_KEYMGMT_get0_description(from_b) != NULL
               && strcmp(EVP_KEYMGMT_get0_description(from_b),
                         "every callback, and every alternative spelling (b)") == 0 ? 1 : 0);
    EVP_KEYMGMT_free(from_b);

    /*
     * ---- the method object ----
     */
    if (full != NULL) {
        const char *name = EVP_KEYMGMT_get0_name(full);
        const char *desc = EVP_KEYMGMT_get0_description(full);

        printf("method.name_matches=%d\n",
               name != NULL && strcmp(name, "KMGM-Full") == 0 ? 1 : 0);
        printf("method.description_matches=%d\n",
               desc != NULL
                   && strcmp(desc,
                             "every callback, and every alternative spelling (a)") == 0
                   ? 1 : 0);
        sayp("method.provider", (const void *) EVP_KEYMGMT_get0_provider(full));
        sayn("method.up_ref", EVP_KEYMGMT_up_ref(full));
        sayn("method.is_a.identity", EVP_KEYMGMT_is_a(full, "KMGM-Full"));
        sayn("method.is_a.alias", EVP_KEYMGMT_is_a(full, "courtkmgmfull"));
        sayn("method.is_a.other", EVP_KEYMGMT_is_a(full, "KMGM-GenOnly"));
        sayn("method.is_a.unknown", EVP_KEYMGMT_is_a(full, "no-such-name"));
        sayn("method.is_a.null_method", EVP_KEYMGMT_is_a(NULL, "KMGM-Full"));

        {
            struct kmgm_names s;

            memset(&s, 0, sizeof s);
            sayn("method.names_do_all.ret",
                 EVP_KEYMGMT_names_do_all(full, kmgm_name_visitor, &s));
            sayn("method.names.count", s.count);
            sayn("method.names.saw_identity", s.saw_identity);
            sayn("method.names.saw_alias", s.saw_alias);
        }
    }

    /*
     * ---- the four descriptor accessors are call-throughs ----
     *
     * `KMGM-Full` publishes all four, `KMGM-LoadOnly` publishes none, and 7.4c's
     * `EVP_PKEY_CTX` is not needed to observe any of them. The identity comparisons say *which*
     * table came back, which is a relation between pointers this probe holds rather than an
     * address.
     */
    reset_counts();
    sayp("params.gettable", (const void *) EVP_KEYMGMT_gettable_params(full));
    sayp("params.settable", (const void *) EVP_KEYMGMT_settable_params(full));
    sayp("params.gen_settable", (const void *) EVP_KEYMGMT_gen_settable_params(full));
    sayp("params.gen_gettable", (const void *) EVP_KEYMGMT_gen_gettable_params(full));
    say_vec("params.vec");
    printf("params.gettable_is_the_first_table=%d\n",
           EVP_KEYMGMT_gettable_params(full) == kmgm_gettable ? 1 : 0);
    printf("params.settable_is_its_own_table=%d\n",
           EVP_KEYMGMT_settable_params(full) == kmgm_settable ? 1 : 0);
    printf("params.gen_settable_is_its_own_table=%d\n",
           EVP_KEYMGMT_gen_settable_params(full) == kmgm_gen_settable ? 1 : 0);
    printf("params.gen_gettable_is_its_own_table=%d\n",
           EVP_KEYMGMT_gen_gettable_params(full) == kmgm_gen_gettable ? 1 : 0);
    say_vec("params.vec.after_identity_calls");

    /* The same four calls on a method that publishes none of them: four NULLs, and no counter
     * moves -- which is what makes each an answer about the *method* rather than about the call. */
    reset_counts();
    sayp("params.gettable.gen_only", (const void *) EVP_KEYMGMT_gettable_params(genonly));
    sayp("params.settable.gen_only", (const void *) EVP_KEYMGMT_settable_params(genonly));
    sayp("params.gen_settable.gen_only",
         (const void *) EVP_KEYMGMT_gen_settable_params(genonly));
    sayp("params.gen_gettable.gen_only",
         (const void *) EVP_KEYMGMT_gen_gettable_params(genonly));
    say_vec("params.vec.gen_only");
    /*
     * A NULL method is **not** observable here: all four accessors read a field of the method
     * before testing the callback, so `EVP_KEYMGMT_gettable_params(NULL)` and its three siblings
     * die with SIGSEGV (exit 139) on the authority. That was measured once, and the boundary is
     * printed rather than compared -- a fault is not an observation, and two sides faulting the
     * same way is not agreement (the runner refuses a signal for exactly that reason). The crate
     * answers NULL instead, which is a real behavioural narrowing and is recorded as
     * `D-KEYMGMT-PARAMS-NULL-1` in `docs/SECURITY_DIVERGENCE_POLICY.md`.
     */
    printf("params.gettable.null_method=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("params.settable.null_method=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("params.gen_settable.null_method=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("params.gen_gettable.null_method=NOT_MEASURED_AUTHORITY_FAULTS\n");

    /*
     * ---- the walk over every provider's methods ----
     */
    {
        struct kmgm_seen s;

        memset(&s, 0, sizeof s);
        EVP_KEYMGMT_do_all_provided(ctx, kmgm_visitor, &s);
        sayn("do_all.count", s.count);
        sayn("do_all.saw_full", s.saw_full);
        sayn("do_all.saw_load_only", s.saw_loadonly);
        sayn("do_all.saw_a_refused_one", s.saw_a_refused_one);
    }
    printf("do_all.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("legacy_alg_fill=NOT_MEASURED_NO_EXPORT_READS_IT_BEFORE_7.4c\n");

    /*
     * ---- release ----
     *
     * `EVP_KEYMGMT_free` releases the method object. The provider's `free` callback is the *key
     * data* destructor and `evp_keymgmt_freedata` is the only caller, so no free here can reach it
     * and the counter must stay where it was. A transcription that read the field as the method's
     * destructor would move it once per method.
     */
    EVP_KEYMGMT_free(full);
    EVP_KEYMGMT_free(loadonly);
    EVP_KEYMGMT_free(genonly);
    EVP_KEYMGMT_free(getpair);
    EVP_KEYMGMT_free(importboth);
    EVP_KEYMGMT_free(exportboth);
    EVP_KEYMGMT_free(nofree);
    EVP_KEYMGMT_free(nohas);
    EVP_KEYMGMT_free(noconstructor);
    EVP_KEYMGMT_free(nogeninit);
    EVP_KEYMGMT_free(nogencleanup);
    EVP_KEYMGMT_free(gethalf);
    EVP_KEYMGMT_free(sethalf);
    EVP_KEYMGMT_free(gengethalf);
    EVP_KEYMGMT_free(gensethalf);
    EVP_KEYMGMT_free(importnodesc);
    EVP_KEYMGMT_free(importnodesc2);
    EVP_KEYMGMT_free(exportnodesc);
    EVP_KEYMGMT_free(gettabletwice);
    EVP_KEYMGMT_free(dupimport);
    EVP_KEYMGMT_free(unknown);
    EVP_KEYMGMT_free(rejected);
    say_vec("final.vec");
    sayn("final.provider_free_calls", k_free);
    sayn("unload.a", OSSL_PROVIDER_unload(a));
    sayn("unload.b", OSSL_PROVIDER_unload(b));
    OSSL_LIB_CTX_free(ctx);
    printf("done=1\n");
    return 0;
}
