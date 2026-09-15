/*
 * RT-LIBCTX -- the library context, differentially.
 *
 * What this court has to establish
 * --------------------------------
 * `OSSL_LIB_CTX` is the object the whole of OpenSSL 3 is parameterised by, and almost
 * none of its contract is in its documentation. What a caller can actually observe is:
 *
 *   * **identity and lifetime.** `OSSL_LIB_CTX_new` hands back a distinct object each
 *     time; `OSSL_LIB_CTX_get0_global_default` hands back *the same* object in every
 *     thread and never a new one; and two of the three values `OSSL_LIB_CTX_free`
 *     accepts -- NULL, and a context that is currently the default for this thread --
 *     are **no-ops**, because `ossl_lib_ctx_is_default` answers 1 for both. A caller
 *     who frees the thread-local default and then uses it is not using freed memory.
 *   * **the default chain.** A NULL context resolves to this thread's default if one
 *     was set and to the global default otherwise, and `OSSL_LIB_CTX_set0_default`
 *     *returns the previous default while setting a new one*, except that passing the
 *     global default as the new one **clears** the thread's slot rather than pointing
 *     it back at the global object.
 *   * **the index registry.** `OSSL_LIB_CTX_get_data(ctx, index)` is a plain switch
 *     with no bounds check, so the *shape* of the table is observable: which index
 *     numbers answer a pointer, which answer NULL, and which answer a pointer into the
 *     context itself. A caller cannot name the indices -- they are declared in
 *     `include/internal/cryptlib.h`, which is not installed -- but it can pass
 *     integers, and this probe does, so the numbers below are written out with the
 *     header they came from. That is also why the probe is written against the
 *     *installed* headers only.
 *   * **`conf_diagnostics` is per-context state**, read and written through a NULL
 *     context as well, so a caller can set it on the default context without naming it.
 *
 * Addresses are never printed. Every observation is a *relation* between two pointers
 * this probe holds (`==`, `!=`) or a presence answer (`NULL` / `nonnull`), because the
 * authority's addresses and the candidate's cannot be equal and printing one would
 * compare the probe's own heap layout rather than the library's behaviour. Relations
 * are the entire observable content of an identity API.
 *
 * The scope of the index table
 * ---------------------------
 * The authority answers a pointer for **every live index** -- eighteen of them -- and
 * each holds a sub-object that a different stratum owns. This stratum owns one: index
 * 21, whose answer is the *address of a field* rather than an allocation, and which is
 * therefore exact as soon as the field exists. The other seventeen are named in
 * `docs/PHASE-6-SUBPHASES.md` with the subphase that fills each, and this probe does
 * not call them: calling one would compare a *missing subsystem* rather than a
 * behavioural divergence, which is the obligation ledger's business, not a court's.
 *
 * So the table below observes two things and prints its own scope:
 *
 *   * the **dead** indices -- -1, 7, 8, 9, 13 and everything from 23 up -- which answer
 *     NULL in the authority because its `switch` has no arm for them, and must answer
 *     NULL in the candidate for the same reason. This is a real test of the boundary,
 *     and it is the one place where a candidate that guessed instead of reading would
 *     differ.
 *   * the **filled** slots, which the candidate claims to have built.
 *
 * `libctx.slots.live`, `.filled` and `.deferred` state the arithmetic, so a reader of
 * the transcript can see the gap without reading this file. When a later subphase fills
 * a slot it adds it to `filled_slots` and the counts move with it.
 *
 * Fault boundaries
 * ----------------
 * One observation deliberately reads a context *after* `OSSL_LIB_CTX_free` returned,
 * to distinguish "the no-op the authority performs" from "a free". That read is only
 * well-defined because the authority keeps the object alive; an implementation that
 * really freed it is reading released memory, which glibc does not fault on for a
 * heap chunk of this size, so the defect surfaces as a differing value rather than as a
 * crash. The hazard is recorded here rather than avoided, because avoiding it would
 * remove the only observation that can see this behaviour at all.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. The
 * `err=` field is the packed `ERR_peek_error()` read immediately after the call and
 * cleared before the next, so it belongs to its own call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

/* ---------------------------------------------------------------- reporting */

#define SAYN(key, expr)                                                       \
    do {                                                                      \
        printf("%s=%d err=%lu\n", (key), (int) (expr), ERR_peek_error());      \
        ERR_clear_error();                                                    \
    } while (0)

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull",
           ERR_peek_error());
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

/*
 * The index numbers, from `include/internal/cryptlib.h` of the admitted authority
 * (`OSSL_LIB_CTX_*_INDEX`). They are not in any installed header, so a consumer that
 * passes one is passing a bare integer -- which is exactly what this probe does.
 *
 *  0 EVP_METHOD_STORE   1 PROVIDER_STORE     2 PROPERTY_DEFN    3 PROPERTY_STRING
 *  4 NAMEMAP            5 DRBG               6 DRBG_NONCE       7 (was CRNG test data)
 *  8 (was THREAD_EVENT) 9 FIPS_PROV         10 ENCODER_STORE   11 DECODER_STORE
 * 12 SELF_TEST_CB      13 BIO_PROV          14 GLOBAL_PROPERTIES
 * 15 STORE_LOADER      16 PROVIDER_CONF     17 BIO_CORE        18 CHILD_PROVIDER
 * 19 THREAD            20 DECODER_CACHE     21 COMP_METHODS    22 INDICATOR_CB
 *
 * `OSSL_LIB_CTX_MAX_INDEXES` is 22 and the function does not consult it; 22 is a live
 * index and 23 is the first one the `default:` arm answers.
 */
#define IDX_COMP_METHODS 21
#define IDX_NAMEMAP 4
#define IDX_SELF_TEST_CB 12
#define IDX_THREAD 19
#define IDX_INDICATOR_CB 22
#define IDX_BIO_CORE 17
#define IDX_PROPERTY_DEFNS 2
#define IDX_PROPERTY_STRING 3
#define IDX_GLOBAL_PROPERTIES 14

/* The eighteen indices the authority answers a pointer for. */
#define LIVE_SLOTS 18

/* The slots this stratum fills. 21 answers `&ctx->comp_methods`, so it is exact as
 * soon as the field exists; 4 is the namemap (6.6b), 19 the thread slot (6.6e),
 * 17 the core BIO globals (6.6c, filled eagerly by `context_init`), and 12 and 22
 * the two callback holders (6.11). 2, 3 and 14 are the property engine (6.7a): the
 * definition cache, the name/value string tables and the global properties holder,
 * all three built eagerly by `context_init` and none of them reachable through any
 * other exported function, which is why the slot table is this subsystem's court.
 * Each later subphase appends its slot here when it lands. */
static const int filled_slots[] = { IDX_COMP_METHODS, IDX_NAMEMAP, IDX_THREAD,
                                    IDX_BIO_CORE, IDX_SELF_TEST_CB,
                                    IDX_INDICATOR_CB, IDX_PROPERTY_DEFNS,
                                    IDX_PROPERTY_STRING, IDX_GLOBAL_PROPERTIES };
#define FILLED_COUNT ((int) (sizeof filled_slots / sizeof filled_slots[0]))

/* The indices the authority answers NULL for, and why: 7 and 8 are slots it reuses
 * or leaves unassigned, 9 is FIPS-only in a profile that is not a FIPS build, 13 was
 * `BIO_PROV` and has no arm, and everything from 23 up is past the end of the switch.
 * -1 is the negative case, which the `default:` arm answers too. */
static const int dead_slots[] = { -1, 7, 8, 9, 13, 23, 24, 31, 255 };
#define DEAD_COUNT ((int) (sizeof dead_slots / sizeof dead_slots[0]))

/* One line per filled slot, for whichever context the caller resolves. */
static void filled_table(const char *prefix, OSSL_LIB_CTX *ctx)
{
    char key[64];
    int i;

    for (i = 0; i < FILLED_COUNT; i++) {
        snprintf(key, sizeof key, "%s.%d", prefix, filled_slots[i]);
        sayp(key, OSSL_LIB_CTX_get_data(ctx, filled_slots[i]));
    }
}

/* One line per dead slot. `idx.<n>` is printed for the NULL context, which resolves
 * through the thread default, and for a fresh non-default context, because a
 * candidate could plausibly get one right and the other wrong. */
static void dead_table(const char *prefix, OSSL_LIB_CTX *ctx)
{
    char key[64];
    int i;

    for (i = 0; i < DEAD_COUNT; i++) {
        snprintf(key, sizeof key, "%s.%d", prefix, dead_slots[i]);
        sayp(key, OSSL_LIB_CTX_get_data(ctx, dead_slots[i]));
    }
}

int main(void)
{
    OSSL_LIB_CTX *gd, *a, *b, *prev;
    void *cm_gd, *cm_a, *cm_b;

    setvbuf(stdout, NULL, _IOLBF, 0);

    sayn("libctx.slots.live", LIVE_SLOTS);
    sayn("libctx.slots.filled", FILLED_COUNT);
    sayn("libctx.slots.deferred", LIVE_SLOTS - FILLED_COUNT);

    /* ------------------------------------------------------- the global default */

    gd = OSSL_LIB_CTX_get0_global_default();
    sayp("gd.nonnull", gd);
    sayn("gd.stable", gd == OSSL_LIB_CTX_get0_global_default());

    /* A NULL context is the default for this thread, and no thread-local default has
     * been set, so the NULL-context answers are the global default's answers. */
    cm_gd = OSSL_LIB_CTX_get_data(gd, IDX_COMP_METHODS);
    sayn("gd.comp_methods.stable",
         OSSL_LIB_CTX_get_data(gd, IDX_COMP_METHODS) == cm_gd);
    sayn("null.comp_methods.eq.gd",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);
    /* `COMP_METHODS` answers `&ctx->comp_methods`, the address of a field inside the
     * object, so it is never equal to the object's own address. */
    sayn("null.comp_methods.ne.gd",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) != (void *) gd);

    filled_table("gslot", gd);
    dead_table("gdead", gd);
    dead_table("ndead", NULL);

    /* ------------------------------------------------------------ a fresh context */

    a = OSSL_LIB_CTX_new();
    b = OSSL_LIB_CTX_new();
    sayp("new.a", a);
    sayp("new.b", b);
    sayn("new.distinct", a != b);

    filled_table("aslot", a);
    dead_table("adead", a);

    cm_a = OSSL_LIB_CTX_get_data(a, IDX_COMP_METHODS);
    cm_b = OSSL_LIB_CTX_get_data(b, IDX_COMP_METHODS);
    sayn("new.comp_methods.stable", cm_a == OSSL_LIB_CTX_get_data(a, IDX_COMP_METHODS));
    /* Each context's field has its own address, so two contexts differ ... */
    sayn("new.comp_methods.distinct", cm_a != cm_b);
    /* ... and a non-default context differs from the default one. */
    sayn("new.comp_methods.ne.gd", cm_a != cm_gd);

    /* --------------------------------------------------- conf_diagnostics is state */

    sayn("cd.new.zero", OSSL_LIB_CTX_get_conf_diagnostics(a));
    OSSL_LIB_CTX_set_conf_diagnostics(a, 7);
    sayn("cd.set7.get", OSSL_LIB_CTX_get_conf_diagnostics(a));
    sayn("cd.other.unaffected", OSSL_LIB_CTX_get_conf_diagnostics(b));
    sayn("cd.null.reads.default", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    OSSL_LIB_CTX_set_conf_diagnostics(NULL, 9);
    sayn("cd.null.set.null.get", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    /* Setting it through NULL touched the default, not `a`. */
    sayn("cd.a.unaffected", OSSL_LIB_CTX_get_conf_diagnostics(a));
    OSSL_LIB_CTX_set_conf_diagnostics(NULL, 0);
    sayn("cd.null.reset", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    /* Any `int` is stored, including a negative one. */
    OSSL_LIB_CTX_set_conf_diagnostics(a, -3);
    sayn("cd.negative", OSSL_LIB_CTX_get_conf_diagnostics(a));
    OSSL_LIB_CTX_set_conf_diagnostics(a, 0);

    /* ------------------------------------------------------ set0_default semantics */

    /* With no thread-local default set, a query returns the global default and, since
     * the argument is NULL, leaves it alone. */
    sayn("sd.query.returns.gd", OSSL_LIB_CTX_set0_default(NULL) == gd);
    sayn("sd.query.leaves.default",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);

    prev = OSSL_LIB_CTX_set0_default(a);
    sayn("sd.set.returns.previous", prev == gd);
    /* The NULL context now resolves to `a`, so both the data table and the diagnostics
     * follow the thread's slot rather than the global object. */
    sayn("sd.set.null.resolves.a",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_a);
    sayn("sd.set.null.data.ne.gd",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) != cm_gd);
    OSSL_LIB_CTX_set_conf_diagnostics(a, 5);
    sayn("sd.set.null.cd.reads.a", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    sayn("sd.query.now.returns.a", OSSL_LIB_CTX_set0_default(NULL) == a);

    /* Passing the *global* default as the new default clears the thread's slot instead
     * of storing the global object in it -- `set_default_context` rewrites it to NULL.
     * The observable consequence is that a query answers the global default again. */
    prev = OSSL_LIB_CTX_set0_default(gd);
    sayn("sd.clear.returns.previous", prev == a);
    sayn("sd.clear.null.resolves.gd",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);
    sayn("sd.clear.query.returns.gd", OSSL_LIB_CTX_set0_default(NULL) == gd);

    /* ---------------------------------------------------------------- free is not */

    /* NULL is a no-op ... */
    OSSL_LIB_CTX_free(NULL);
    sayn("free.null.noop",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);

    /* ... and so is the global default, which `get0_global_default` must keep handing
     * back afterwards, still usable. */
    OSSL_LIB_CTX_free(gd);
    sayp("free.gd.alive.comp_methods", OSSL_LIB_CTX_get_data(gd, IDX_COMP_METHODS));
    sayn("free.gd.same.object", OSSL_LIB_CTX_get0_global_default() == gd);
    sayn("free.gd.cd", OSSL_LIB_CTX_get_conf_diagnostics(gd));

    /* A context that is not the default really is released; the observable statement is
     * that the library is still consistent afterwards. */
    OSSL_LIB_CTX_free(a);
    sayn("free.a.gd.ok",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);

    /* The thread-local default is a no-op too. `b` is read afterwards, which is
     * well-defined only because the authority kept it alive -- see the header. */
    sayn("free.threaddefault.installed", OSSL_LIB_CTX_set0_default(b) == gd);
    OSSL_LIB_CTX_free(b);
    sayn("free.threaddefault.cd", OSSL_LIB_CTX_get_conf_diagnostics(b));
    sayn("free.threaddefault.data.nonnull",
         OSSL_LIB_CTX_get_data(b, IDX_COMP_METHODS) != NULL);
    sayn("free.threaddefault.still.default", OSSL_LIB_CTX_set0_default(NULL) == b);
    sayn("free.threaddefault.restore", OSSL_LIB_CTX_set0_default(gd) == b);

    /* --------------------------------------------------------------- nothing raised */

    sayn("err.empty", ERR_peek_error() == 0);
    says("done", "rt-libctx");
    return 0;
}
