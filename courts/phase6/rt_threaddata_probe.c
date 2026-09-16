/*
 * RT-THREADDATA -- the per-context thread slot and its two accessors, differentially.
 *
 * What this court has to establish
 * --------------------------------
 * `OSSL_get_max_threads` and `OSSL_set_max_threads` are two locks and a field, so
 * the interesting part is not the arithmetic -- it is *which object* the field
 * lives in, and what happens when there is no object. Measured against the
 * admitted authority, that is three things:
 *
 *   * the counter is per **context**. `OSSL_set_max_threads(ctx_a, n)` must not
 *     move `OSSL_get_max_threads(ctx_b)`, and the default context is one of the
 *     contexts rather than a special case.
 *   * a NULL context resolves through the library context default chain, so the
 *     answer follows whatever this thread currently defaults to -- which the
 *     probe observes by installing a default and reading through NULL.
 *   * `OSSL_set_max_threads` answers **1** and the value is stored verbatim: no
 *     range check, so `UINT64_MAX` is legal to set and to read back. A
 *     `uint64_t` counter that is clipped, or a `set` that refuses a large value,
 *     would be a plausible implementation and a wrong one.
 *
 * The slot itself is observed by `RT-LIBCTX`, which sweeps the library context's
 * index table; this probe never touches `OSSL_LIB_CTX_get_data`, because the
 * index numbers are internal and this court's subject is the two accessors.
 *
 * Every value is printed as an unsigned decimal, so a truncation or a sign
 * mistake is visible rather than hidden behind a truthy comparison.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. The
 * `err=` field is the packed `ERR_peek_error()` read immediately after the call and
 * cleared before the next, so it belongs to its own call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/thread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void sayu(const char *key, uint64_t v)
{
    printf("%s=%llu err=%lu\n", key, (unsigned long long) v, ERR_peek_error());
    ERR_clear_error();
}

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull",
           ERR_peek_error());
    ERR_clear_error();
}

/* ------------------------------------------------------------------ *
 * 6.6e-ii: the thread-stop handler, and `OPENSSL_atexit`
 * ------------------------------------------------------------------ */

/* The provider's context, so the handler can check the argument it was given. */
static char court_provctx_marker;

/* What the core's `thread_start` entry was able to do, and what the handler saw. */
static int ts_available;
static int ts_ret = -1;
static int stop_calls;
static int stop_arg_matches;

/* The `OPENSSL_atexit` handlers, and the order they ran in. */
static int atexit_calls;
static int atexit_order[2];

static void court_stop_handler(void *arg)
{
    stop_calls++;
    if (arg == (void *)&court_provctx_marker)
        stop_arg_matches = 1;
}

static void court_atexit_first(void)
{
    atexit_order[atexit_calls < 2 ? atexit_calls : 1] = 1;
    atexit_calls++;
}

static void court_atexit_second(void)
{
    atexit_order[atexit_calls < 2 ? atexit_calls : 1] = 2;
    atexit_calls++;
}

/* The provider publishes nothing: this probe's subject is the *core* entry the
 * provider is handed, and a provider that publishes no algorithms is the smallest
 * thing that can call it. */
static const OSSL_DISPATCH court_out[] = {
    { 0, NULL }
};

static int court_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out, void **provctx)
{
    const OSSL_DISPATCH *f;
    OSSL_FUNC_core_thread_start_fn *ts = NULL;

    /* `OSSL_FUNC_core_thread_start(x)` is a **cast of the entry it is handed**, not a
     * search: `OSSL_CORE_MAKE_FUNC` expands to `return (OSSL_FUNC_##name##_fn
     * *)opf->function;`. So the table must be walked and the matching entry handed to
     * the accessor. Applying it to `in` directly asks entry 0 -- `core_gettable_params`
     * -- to register a thread-stop handler, which returns whatever the callee's `eax`
     * happens to hold. The first version of this probe did exactly that and both sides
     * printed a garbage large negative number, differing from each other; the defect
     * was the probe's, and the lesson is already written down in
     * `src/context/dispatch.rs`. */
    for (f = in; f != NULL && f->function_id != 0; f++) {
        if (f->function_id == OSSL_FUNC_CORE_THREAD_START) {
            ts = OSSL_FUNC_core_thread_start(f);
            break;
        }
    }

    ts_available = ts != NULL;
    if (ts != NULL)
        ts_ret = ts(handle, court_stop_handler, &court_provctx_marker);
    *out = court_out;
    *provctx = &court_provctx_marker;
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *gd, *a, *b, *prev;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* The two functions do not need the context to exist first, but a context is
     * what they read, so this establishes that the global default is there. */
    gd = OSSL_LIB_CTX_get0_global_default();
    sayp("gd.nonnull", gd);

    /* ------------------------------------------------ a fresh, non-default context */

    a = OSSL_LIB_CTX_new();
    b = OSSL_LIB_CTX_new();
    sayp("new.a", a);
    sayp("new.b", b);
    sayn("new.distinct", a != b);

    /* A fresh context's counter is zero, and it is zero for each of them. */
    sayu("get.a.initial", OSSL_get_max_threads(a));
    sayu("get.b.initial", OSSL_get_max_threads(b));

    sayn("set.a.7", OSSL_set_max_threads(a, 7));
    sayu("get.a.7", OSSL_get_max_threads(a));
    /* Per-context: `b` did not move. */
    sayu("get.b.after.a.7", OSSL_get_max_threads(b));

    /* Stored verbatim, with no range check. */
    sayn("set.b.max", OSSL_set_max_threads(b, UINT64_MAX));
    sayu("get.b.max", OSSL_get_max_threads(b));
    sayu("get.a.after.b.max", OSSL_get_max_threads(a));

    /* Zero is a value, not "unset". */
    sayn("set.a.zero", OSSL_set_max_threads(a, 0));
    sayu("get.a.zero", OSSL_get_max_threads(a));
    sayu("get.b.still.max", OSSL_get_max_threads(b));
    sayn("set.b.zero", OSSL_set_max_threads(b, 0));

    /* ------------------------------------------------------ the NULL context */

    /* No thread-local default is installed, so NULL is the global default, whose
     * counter starts at zero and is the same object `gd` names. */
    sayu("get.null.initial", OSSL_get_max_threads(NULL));
    sayn("set.gd.9", OSSL_set_max_threads(gd, 9));
    sayu("get.null.after.gd.9", OSSL_get_max_threads(NULL));
    sayu("get.gd.9", OSSL_get_max_threads(gd));
    sayn("set.null.5", OSSL_set_max_threads(NULL, 5));
    sayu("get.null.5", OSSL_get_max_threads(NULL));
    sayu("get.gd.after.null.5", OSSL_get_max_threads(gd));
    /* The non-default contexts were not touched by any of that. */
    sayu("get.a.after.null", OSSL_get_max_threads(a));
    sayn("set.gd.zero", OSSL_set_max_threads(gd, 0));

    /* ------------------------------------------------- installing a default */

    /* Once this thread defaults to `a`, the NULL context is `a`, so the same
     * accessor answers `a`'s value. That is the whole reason the accessor takes a
     * context it is allowed to be given as NULL. */
    sayn("set.a.11", OSSL_set_max_threads(a, 11));
    sayu("null.before.default", OSSL_get_max_threads(NULL));
    prev = OSSL_LIB_CTX_set0_default(a);
    sayn("default.installed", prev == gd);
    sayu("null.after.default", OSSL_get_max_threads(NULL));
    sayu("explicit.a.after.default", OSSL_get_max_threads(a));
    /* `b` is still `b`. */
    sayu("explicit.b.after.default", OSSL_get_max_threads(b));

    /* Restoring the global default restores the NULL answer, and it must restore
     * it as *the global object*, not as a copy of it. */
    sayn("default.restore", OSSL_LIB_CTX_set0_default(gd) == a);
    sayu("null.after.restore", OSSL_get_max_threads(NULL));
    sayn("set.null.13", OSSL_set_max_threads(NULL, 13));
    sayu("get.gd.13", OSSL_get_max_threads(gd));
    sayn("set.gd.zero2", OSSL_set_max_threads(gd, 0));

    /* ------------------------------------------------- 6.6e-ii: the thread-stop handler */

    /* The only public way to register a thread-stop handler is the core dispatch
     * entry a provider is handed, so this declares one. That is also the point:
     * `ossl_init_thread_start` has no exported symbol, and a provider is the one
     * caller the ABI admits. */
    sayn("thread_start.add_builtin",
         OSSL_PROVIDER_add_builtin(NULL, "rt-td", court_init));
    {
        OSSL_PROVIDER *p = OSSL_PROVIDER_load(NULL, "rt-td");
        sayp("thread_start.provider", p);
        /* The entry is *published*, which is a compatibility fact: id 3 was absent
         * from the core table until 6.6e-ii, and a provider compiled against a 3.x
         * that has it would find NULL here. */
        sayn("thread_start.accessor.nonnull", ts_available);
        /* And it answered the registration's result rather than a value of its own. */
        sayn("thread_start.ret", ts_ret);
        sayn("stop.before", stop_calls);
        OPENSSL_thread_stop();
        sayn("stop.calls", stop_calls);
        /* The argument the core passes through is the one the provider registered. */
        sayn("stop.arg_matches", stop_arg_matches);
        /* The second call is safe and runs nothing: the list was unlinked and its
         * head released by the first. */
        OPENSSL_thread_stop();
        sayn("stop.again", stop_calls);
        if (p != NULL)
            OSSL_PROVIDER_unload(p);
    }

    /* ------------------------------------------------------------------ cleanup */

    /* `a` and `b` are not the default, so these really release them. */
    OSSL_LIB_CTX_free(a);
    OSSL_LIB_CTX_free(b);
    sayp("free.gd.alive", OSSL_LIB_CTX_get0_global_default());

    sayn("err.empty", ERR_peek_error() == 0);

    /* ------------------------------------------------- 6.6e-ii: `OPENSSL_atexit` */

    /* `OPENSSL_atexit` in this profile is a linked-list push, because the DSO-pinning
     * block is guarded by `!defined(OPENSSL_USE_NODELETE)` and `configdata.pm` records
     * `-DOPENSSL_USE_NODELETE`. So what there is to observe is the push's answer and
     * the order the drain runs them in: LIFO, like the handler table. */
    sayn("atexit.ret.first", OPENSSL_atexit(court_atexit_first));
    sayn("atexit.ret.second", OPENSSL_atexit(court_atexit_second));
    sayn("atexit.before", atexit_calls);

    /* `OPENSSL_cleanup` drains them, and it stops this thread's handlers first -- so
     * the count below is one higher than the last `stop.calls`, and that *is* the
     * authority's order rather than an artefact. `printf` is used rather than `sayn`
     * because the error state is gone by this point and `ERR_peek_error` would be
     * measuring the teardown rather than the call. */
    OPENSSL_cleanup();
    printf("atexit.calls=%d\n", atexit_calls);
    printf("atexit.first_ran=%d\n", atexit_order[0]);
    printf("atexit.second_ran=%d\n", atexit_order[1]);
    printf("stop.after_cleanup=%d\n", stop_calls);
    printf("done=rt-threaddata\n");
    return 0;
}
